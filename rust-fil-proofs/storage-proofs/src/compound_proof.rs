use rayon::prelude::*;

use anyhow::{ensure, Context};
use bellperson::{groth16, Circuit};
use fil_sapling_crypto::jubjub::JubjubEngine;
use log::info;
use rand::rngs::OsRng;

use crate::circuit::multi_proof::MultiProof;
use crate::error::Result;
use crate::parameter_cache::{CacheableParameters, ParameterSetMetadata};
use crate::partitions;
use crate::proof::ProofScheme;

#[derive(Clone,Debug)]
pub struct SetupParams<'a, S: ProofScheme<'a>> {
    pub vanilla_params: <S as ProofScheme<'a>>::SetupParams,
    pub partitions: Option<usize>,
    /// High priority (always runs on GPU) == true
    pub priority: bool,
}

#[derive(Clone,Debug)]
pub struct PublicParams<'a, S: ProofScheme<'a>> {
    pub vanilla_params: S::PublicParams,
    pub partitions: Option<usize>,
    pub priority: bool,
}

/// CircuitComponent exists so parent components can pass private inputs to their subcomponents
/// when calling CompoundProof::circuit directly. In general, there are no internal private inputs,
/// and a default value will be passed. CompoundProof::circuit implementations should exhibit
/// default behavior when passed a default ComponentPrivateinputs.
pub trait CircuitComponent {
    type ComponentPrivateInputs: Default + Clone;
}

/// The CompoundProof trait bundles a proof::ProofScheme and a bellperson::Circuit together.
/// It provides methods equivalent to those provided by proof::ProofScheme (setup, prove, verify).
/// See documentation at proof::ProofScheme for details.
/// Implementations should generally only need to supply circuit and generate_public_inputs.
/// The remaining trait methods are used internally and implement the necessary plumbing.
pub trait CompoundProof<
    'a,
    E: JubjubEngine,
    S: ProofScheme<'a>,
    C: Circuit<E> + CircuitComponent + Send,
> where
    S::Proof: Sync + Send,
    S::PublicParams: ParameterSetMetadata + Sync + Send,
    S::PublicInputs: Clone + Sync,
    Self: CacheableParameters<E, C, S::PublicParams>,
{
    // setup is equivalent to ProofScheme::setup.
    fn setup(sp: &SetupParams<'a, S>) -> Result<PublicParams<'a, S>>
    where
        E::Params: Sync,
    {
        Ok(PublicParams {
            vanilla_params: S::setup(&sp.vanilla_params)?,
            partitions: sp.partitions,
            priority: sp.priority,
        })
    }

    fn partition_count(public_params: &PublicParams<'a, S>) -> usize {
        match public_params.partitions {
            None => 1,
            Some(0) => panic!("cannot specify zero partitions"),
            Some(k) => k,
        }
    }

    /// prove is equivalent to ProofScheme::prove.
    fn prove<'b>(
        pub_params: &PublicParams<'a, S>,
        pub_in: &S::PublicInputs,
        priv_in: &S::PrivateInputs,
        groth_params: &'b groth16::MappedParameters<E>,
    ) -> Result<MultiProof<'b, E>>
    where
        E::Params: Sync,
    {
        let partitions = Self::partition_count(pub_params);
        let partition_count = Self::partition_count(pub_params);

        // This will always run at least once, since there cannot be zero partitions.
        ensure!(partition_count > 0, "There must be partitions");

        info!("vanilla_proof:start");
        let vanilla_proofs =
            S::prove_all_partitions(&pub_params.vanilla_params, &pub_in, priv_in, partitions)?;

        info!("vanilla_proof:finish");

        let sanity_check =
            S::verify_all_partitions(&pub_params.vanilla_params, &pub_in, &vanilla_proofs)?;
        ensure!(sanity_check, "sanity check failed");

        info!("snark_proof:start");
        let groth_proofs = Self::circuit_proofs(
            pub_in,
            vanilla_proofs,
            &pub_params.vanilla_params,
            groth_params,
            pub_params.priority,
        )?;
        info!("snark_proof:finish");

        Ok(MultiProof::new(groth_proofs, &groth_params.vk))
    }

    // verify is equivalent to ProofScheme::verify.
    fn verify<'b>(
        public_params: &PublicParams<'a, S>,
        public_inputs: &S::PublicInputs,
        multi_proof: &MultiProof<'b, E>,
        requirements: &S::Requirements,
    ) -> Result<bool> {
        ensure!(
            multi_proof.circuit_proofs.len() == Self::partition_count(public_params),
            "Inconsistent inputs"
        );

        let vanilla_public_params = &public_params.vanilla_params;
        let pvk = groth16::prepare_batch_verifying_key(&multi_proof.verifying_key);

        if !<S as ProofScheme>::satisfies_requirements(
            &public_params.vanilla_params,
            requirements,
            multi_proof.circuit_proofs.len(),
        ) {
            return Ok(false);
        }

        let inputs: Vec<_> = (0..multi_proof.circuit_proofs.len())
            .into_par_iter()
            .map(|k| Self::generate_public_inputs(public_inputs, vanilla_public_params, Some(k)))
            .collect::<Result<_>>()?;
        let proofs: Vec<_> = multi_proof.circuit_proofs.iter().collect();

        let res = groth16::verify_proofs_batch(&pvk, &mut rand::rngs::OsRng, &proofs, &inputs)?;

        Ok(res)
    }

    /// Efficiently verify multiple proofs.
    fn batch_verify<'b>(
        public_params: &PublicParams<'a, S>,
        public_inputs: &[S::PublicInputs],
        multi_proofs: &[MultiProof<'b, E>],
        requirements: &S::Requirements,
    ) -> Result<bool> {
        ensure!(
            public_inputs.len() == multi_proofs.len(),
            "Inconsistent inputs"
        );
        for proof in multi_proofs {
            ensure!(
                proof.circuit_proofs.len() == Self::partition_count(public_params),
                "Inconsistent inputs"
            );
        }
        ensure!(!public_inputs.is_empty(), "Cannot verify empty proofs");

        let vanilla_public_params = &public_params.vanilla_params;
        // just use the first one, the must be equal any way
        let pvk = groth16::prepare_batch_verifying_key(&multi_proofs[0].verifying_key);

        for multi_proof in multi_proofs.iter() {
            if !<S as ProofScheme>::satisfies_requirements(
                &public_params.vanilla_params,
                requirements,
                multi_proof.circuit_proofs.len(),
            ) {
                return Ok(false);
            }
        }

        let inputs: Vec<_> = multi_proofs
            .par_iter()
            .zip(public_inputs.par_iter())
            .flat_map(|(multi_proof, pub_inputs)| {
                (0..multi_proof.circuit_proofs.len())
                    .into_par_iter()
                    .map(|k| {
                        Self::generate_public_inputs(pub_inputs, vanilla_public_params, Some(k))
                    })
                    .collect::<Result<Vec<_>>>()
                    .expect("Invalid public inputs") // TODO: improve error handling
            })
            .collect::<Vec<_>>();
        let circuit_proofs: Vec<_> = multi_proofs
            .iter()
            .flat_map(|m| m.circuit_proofs.iter())
            .collect();

        let res = groth16::verify_proofs_batch(
            &pvk,
            &mut rand::rngs::OsRng,
            &circuit_proofs[..],
            &inputs,
        )?;

        Ok(res)
    }

    /// circuit_proof creates and synthesizes a circuit from concrete params/inputs, then generates a
    /// groth proof from it. It returns a groth proof.
    /// circuit_proof is used internally and should neither be called nor implemented outside of
    /// default trait methods.
    fn circuit_proofs(
        pub_in: &S::PublicInputs,
        vanilla_proof: Vec<S::Proof>,
        pub_params: &S::PublicParams,
        groth_params: &groth16::MappedParameters<E>,
        priority: bool,
    ) -> Result<Vec<groth16::Proof<E>>> {
        let mut rng = OsRng;

        let circuits = vanilla_proof
            .into_par_iter()
            .map(|vanilla_proof| {
                Self::circuit(
                    &pub_in,
                    C::ComponentPrivateInputs::default(),
                    &vanilla_proof,
                    &pub_params,
                )
            })
            .collect::<Result<Vec<_>>>()?;

        let groth_proofs = if priority {
            groth16::create_random_proof_batch_in_priority(circuits, groth_params, &mut rng)?
        } else {
            groth16::create_random_proof_batch(circuits, groth_params, &mut rng)?
        };

        groth_proofs
            .into_iter()
            .map(|groth_proof| {
                let mut proof_vec = vec![];
                groth_proof.write(&mut proof_vec)?;
                let gp = groth16::Proof::<E>::read(&proof_vec[..])?;
                Ok(gp)
            })
            .collect()
    }

    /// generate_public_inputs generates public inputs suitable for use as input during verification
    /// of a proof generated from this CompoundProof's bellperson::Circuit (C). These inputs correspond
    /// to those allocated when C is synthesized.
    fn generate_public_inputs(
        pub_in: &S::PublicInputs,
        pub_params: &S::PublicParams,
        partition_k: Option<usize>,
    ) -> Result<Vec<E::Fr>>;

    /// circuit constructs an instance of this CompoundProof's bellperson::Circuit.
    /// circuit takes PublicInputs, PublicParams, and Proof from this CompoundProof's proof::ProofScheme (S)
    /// and uses them to initialize Circuit fields which will be used to construct public and private
    /// inputs during circuit synthesis.
    fn circuit(
        public_inputs: &S::PublicInputs,
        component_private_inputs: C::ComponentPrivateInputs,
        vanilla_proof: &S::Proof,
        public_param: &S::PublicParams,
    ) -> Result<C>;

    fn blank_circuit(public_params: &S::PublicParams) -> C;

    fn groth_params(public_params: &S::PublicParams) -> Result<groth16::MappedParameters<E>> {
        Self::get_groth_params(Self::blank_circuit(public_params), public_params)
    }

    fn verifying_key(public_params: &S::PublicParams) -> Result<groth16::VerifyingKey<E>> {
        Self::get_verifying_key(Self::blank_circuit(public_params), public_params)
    }

    fn circuit_for_test(
        public_parameters: &PublicParams<'a, S>,
        public_inputs: &S::PublicInputs,
        private_inputs: &S::PrivateInputs,
    ) -> Result<(C, Vec<E::Fr>)> {
        let vanilla_params = &public_parameters.vanilla_params;
        let partition_count = partitions::partition_count(public_parameters.partitions);
        let vanilla_proofs = S::prove_all_partitions(
            vanilla_params,
            public_inputs,
            private_inputs,
            partition_count,
        )
        .context("failed to generate partition proofs")?;

        ensure!(
            vanilla_proofs.len() == partition_count,
            "Vanilla proofs didn't match number of partitions."
        );

        let partitions_are_verified =
            S::verify_all_partitions(vanilla_params, &public_inputs, &vanilla_proofs)
                .context("failed to verify partition proofs")?;

        ensure!(partitions_are_verified, "Vanilla proof didn't verify.");

        // Some(0) because we only return a circuit and inputs for the first partition.
        // It would be more thorough to return all, though just checking one is probably
        // fine for verifying circuit construction.
        let partition_pub_in = S::with_partition(public_inputs.clone(), Some(0));
        let inputs = Self::generate_public_inputs(&partition_pub_in, vanilla_params, Some(0))?;

        let circuit = Self::circuit(
            &partition_pub_in,
            C::ComponentPrivateInputs::default(),
            &vanilla_proofs[0],
            vanilla_params,
        )?;

        Ok((circuit, inputs))
    }
}