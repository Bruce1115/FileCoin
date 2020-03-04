use std::sync::Arc;

use ff::{Field, PrimeField};
use futures::Future;
use groupy::{CurveAffine, CurveProjective};
use paired::Engine;
use rand_core::RngCore;
use rayon::prelude::*;

use super::{ParameterSource, Proof};
use crate::domain::{create_fft_kernel, EvaluationDomain, Scalar};
use crate::gpu::LockedKernel;
use crate::multicore::Worker;
use crate::multiexp::{create_multiexp_kernel, multiexp, DensityTracker, FullDensity};
use crate::{
    Circuit, ConstraintSystem, Index, LinearCombination, SynthesisError, Variable, BELLMAN_VERSION,
};
use log::info;

#[cfg(feature = "gpu")]
use crate::gpu::PriorityLock;

fn eval<E: Engine>(
    lc: &LinearCombination<E>,
    mut input_density: Option<&mut DensityTracker>,
    mut aux_density: Option<&mut DensityTracker>,
    input_assignment: &[E::Fr],
    aux_assignment: &[E::Fr],
) -> E::Fr {
    let mut acc = E::Fr::zero();

    for &(index, coeff) in lc.0.iter() {
        let mut tmp;

        match index {
            Variable(Index::Input(i)) => {
                tmp = input_assignment[i];
                if let Some(ref mut v) = input_density {
                    v.inc(i);
                }
            }
            Variable(Index::Aux(i)) => {
                tmp = aux_assignment[i];
                if let Some(ref mut v) = aux_density {
                    v.inc(i);
                }
            }
        }

        if coeff == E::Fr::one() {
            acc.add_assign(&tmp);
        } else {
            tmp.mul_assign(&coeff);
            acc.add_assign(&tmp);
        }
    }

    acc
}

struct ProvingAssignment<E: Engine> {
    // Density of queries
    a_aux_density: DensityTracker,
    b_input_density: DensityTracker,
    b_aux_density: DensityTracker,

    // Evaluations of A, B, C polynomials
    a: Vec<Scalar<E>>,
    b: Vec<Scalar<E>>,
    c: Vec<Scalar<E>>,

    // Assignments of variables
    input_assignment: Vec<E::Fr>,
    aux_assignment: Vec<E::Fr>,
}

impl<E: Engine> ConstraintSystem<E> for ProvingAssignment<E> {
    type Root = Self;

    fn alloc<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.aux_assignment.push(f()?);
        self.a_aux_density.add_element();
        self.b_aux_density.add_element();

        Ok(Variable(Index::Aux(self.aux_assignment.len() - 1)))
    }

    fn alloc_input<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.input_assignment.push(f()?);
        self.b_input_density.add_element();

        Ok(Variable(Index::Input(self.input_assignment.len() - 1)))
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
        LB: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
        LC: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
    {
        let a = a(LinearCombination::zero());
        let b = b(LinearCombination::zero());
        let c = c(LinearCombination::zero());

        self.a.push(Scalar(eval(
            &a,
            // Inputs have full density in the A query
            // because there are constraints of the
            // form x * 0 = 0 for each input.
            None,
            Some(&mut self.a_aux_density),
            &self.input_assignment,
            &self.aux_assignment,
        )));
        self.b.push(Scalar(eval(
            &b,
            Some(&mut self.b_input_density),
            Some(&mut self.b_aux_density),
            &self.input_assignment,
            &self.aux_assignment,
        )));
        self.c.push(Scalar(eval(
            &c,
            // There is no C polynomial query,
            // though there is an (beta)A + (alpha)B + C
            // query for all aux variables.
            // However, that query has full density.
            None,
            None,
            &self.input_assignment,
            &self.aux_assignment,
        )));
    }

    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn pop_namespace(&mut self) {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}

pub fn create_random_proof_batch_priority<E, C, R, P: ParameterSource<E>>(
    circuits: Vec<C>,
    params: P,
    rng: &mut R,
    priority: bool,
) -> Result<Vec<Proof<E>>, SynthesisError>
where
    E: Engine,
    C: Circuit<E> + Send,
    R: RngCore,
{
    let r_s = (0..circuits.len()).map(|_| E::Fr::random(rng)).collect();
    let s_s = (0..circuits.len()).map(|_| E::Fr::random(rng)).collect();

    create_proof_batch_priority::<E, C, P>(circuits, params, r_s, s_s, priority)
}

pub fn create_proof_batch_priority<E, C, P: ParameterSource<E>>(
    circuits: Vec<C>,
    mut params: P,
    r_s: Vec<E::Fr>,
    s_s: Vec<E::Fr>,
    priority: bool,
) -> Result<Vec<Proof<E>>, SynthesisError>
where
    E: Engine,
    C: Circuit<E> + Send,
{
    info!("Bellperson {} is being used!", BELLMAN_VERSION);

    let mut provers = circuits
        .into_par_iter()
        .map(|circuit| -> Result<_, SynthesisError> {
            let mut prover = ProvingAssignment {
                a_aux_density: DensityTracker::new(),
                b_input_density: DensityTracker::new(),
                b_aux_density: DensityTracker::new(),
                a: vec![],
                b: vec![],
                c: vec![],
                input_assignment: vec![],
                aux_assignment: vec![],
            };

            prover.alloc_input(|| "", || Ok(E::Fr::one()))?;

            circuit.synthesize(&mut prover)?;

            for i in 0..prover.input_assignment.len() {
                prover.enforce(|| "", |lc| lc + Variable(Index::Input(i)), |lc| lc, |lc| lc);
            }

            Ok(prover)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let worker = Worker::new();
    let input_len = provers[0].input_assignment.len();
    let vk = params.get_vk(input_len)?;
    let n = provers[0].a.len();

    // Make sure all circuits have the same input len.
    for prover in &provers {
        assert_eq!(
            prover.a.len(),
            n,
            "only equaly sized circuits are supported"
        );
    }

    let mut log_d = 0u32;
    while (1 << log_d) < n {
        log_d += 1;
    }

    #[cfg(feature = "gpu")]
    let prio_lock = if priority {
        Some(PriorityLock::lock())
    } else {
        None
    };

    let mut fft_kern = LockedKernel::new(|| create_fft_kernel::<E>(log_d), priority);

    let a_s = provers
        .iter_mut()
        .map(|prover| {
            let mut a =
                EvaluationDomain::from_coeffs(std::mem::replace(&mut prover.a, Vec::new()))?;
            let mut b =
                EvaluationDomain::from_coeffs(std::mem::replace(&mut prover.b, Vec::new()))?;
            let mut c =
                EvaluationDomain::from_coeffs(std::mem::replace(&mut prover.c, Vec::new()))?;

            a.ifft(&worker, fft_kern.get())?;
            a.coset_fft(&worker, fft_kern.get())?;
            b.ifft(&worker, fft_kern.get())?;
            b.coset_fft(&worker, fft_kern.get())?;
            c.ifft(&worker, fft_kern.get())?;
            c.coset_fft(&worker, fft_kern.get())?;

            a.mul_assign(&worker, &b);
            drop(b);
            a.sub_assign(&worker, &c);
            drop(c);
            a.divide_by_z_on_coset(&worker);
            a.icoset_fft(&worker, fft_kern.get())?;
            let mut a = a.into_coeffs();
            let a_len = a.len() - 1;
            a.truncate(a_len);

            Ok(Arc::new(
                a.into_iter().map(|s| s.0.into_repr()).collect::<Vec<_>>(),
            ))
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    drop(fft_kern);
    let mut multiexp_kern = LockedKernel::new(|| create_multiexp_kernel::<E>(), priority);

    let h_s = a_s
        .into_iter()
        .map(|a| {
            let h = multiexp(
                &worker,
                params.get_h(a.len())?,
                FullDensity,
                a,
                multiexp_kern.get(),
            );
            Ok(h)
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    let input_assignments = provers
        .par_iter_mut()
        .map(|prover| {
            let input_assignment = std::mem::replace(&mut prover.input_assignment, Vec::new());
            Arc::new(
                input_assignment
                    .into_iter()
                    .map(|s| s.into_repr())
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();

    let aux_assignments = provers
        .par_iter_mut()
        .map(|prover| {
            let aux_assignment = std::mem::replace(&mut prover.aux_assignment, Vec::new());
            Arc::new(
                aux_assignment
                    .into_iter()
                    .map(|s| s.into_repr())
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();

    let l_s = aux_assignments
        .iter()
        .map(|aux_assignment| {
            let l = multiexp(
                &worker,
                params.get_l(aux_assignment.len())?,
                FullDensity,
                aux_assignment.clone(),
                multiexp_kern.get(),
            );
            Ok(l)
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    let inputs = provers
        .into_iter()
        .zip(input_assignments.iter())
        .zip(aux_assignments.iter())
        .map(|((prover, input_assignment), aux_assignment)| {
            let a_aux_density_total = prover.a_aux_density.get_total_density();

            let (a_inputs_source, a_aux_source) =
                params.get_a(input_assignment.len(), a_aux_density_total)?;

            let a_inputs = multiexp(
                &worker,
                a_inputs_source,
                FullDensity,
                input_assignment.clone(),
                multiexp_kern.get(),
            );

            let a_aux = multiexp(
                &worker,
                a_aux_source,
                Arc::new(prover.a_aux_density),
                aux_assignment.clone(),
                multiexp_kern.get(),
            );

            let b_input_density = Arc::new(prover.b_input_density);
            let b_input_density_total = b_input_density.get_total_density();
            let b_aux_density = Arc::new(prover.b_aux_density);
            let b_aux_density_total = b_aux_density.get_total_density();

            let (b_g1_inputs_source, b_g1_aux_source) =
                params.get_b_g1(b_input_density_total, b_aux_density_total)?;

            let b_g1_inputs = multiexp(
                &worker,
                b_g1_inputs_source,
                b_input_density.clone(),
                input_assignment.clone(),
                multiexp_kern.get(),
            );
            let b_g1_aux = multiexp(
                &worker,
                b_g1_aux_source,
                b_aux_density.clone(),
                aux_assignment.clone(),
                multiexp_kern.get(),
            );

            let (b_g2_inputs_source, b_g2_aux_source) =
                params.get_b_g2(b_input_density_total, b_aux_density_total)?;

            let b_g2_inputs = multiexp(
                &worker,
                b_g2_inputs_source,
                b_input_density,
                input_assignment.clone(),
                multiexp_kern.get(),
            );
            let b_g2_aux = multiexp(
                &worker,
                b_g2_aux_source,
                b_aux_density,
                aux_assignment.clone(),
                multiexp_kern.get(),
            );

            Ok((
                a_inputs,
                a_aux,
                b_g1_inputs,
                b_g1_aux,
                b_g2_inputs,
                b_g2_aux,
            ))
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    drop(multiexp_kern);

    #[cfg(feature = "gpu")]
    drop(prio_lock);

    let proofs = h_s
        .into_iter()
        .zip(l_s.into_iter())
        .zip(inputs.into_iter())
        .zip(r_s.into_iter())
        .zip(s_s.into_iter())
        .map(
            |(
                (((h, l), (a_inputs, a_aux, b_g1_inputs, b_g1_aux, b_g2_inputs, b_g2_aux)), r),
                s,
            )| {
                if vk.delta_g1.is_zero() || vk.delta_g2.is_zero() {
                    // If this element is zero, someone is trying to perform a
                    // subversion-CRS attack.
                    return Err(SynthesisError::UnexpectedIdentity);
                }

                let mut g_a = vk.delta_g1.mul(r);
                g_a.add_assign_mixed(&vk.alpha_g1);
                let mut g_b = vk.delta_g2.mul(s);
                g_b.add_assign_mixed(&vk.beta_g2);
                let mut g_c;
                {
                    let mut rs = r;
                    rs.mul_assign(&s);

                    g_c = vk.delta_g1.mul(rs);
                    g_c.add_assign(&vk.alpha_g1.mul(s));
                    g_c.add_assign(&vk.beta_g1.mul(r));
                }
                let mut a_answer = a_inputs.wait()?;
                a_answer.add_assign(&a_aux.wait()?);
                g_a.add_assign(&a_answer);
                a_answer.mul_assign(s);
                g_c.add_assign(&a_answer);

                let mut b1_answer = b_g1_inputs.wait()?;
                b1_answer.add_assign(&b_g1_aux.wait()?);
                let mut b2_answer = b_g2_inputs.wait()?;
                b2_answer.add_assign(&b_g2_aux.wait()?);

                g_b.add_assign(&b2_answer);
                b1_answer.mul_assign(r);
                g_c.add_assign(&b1_answer);
                g_c.add_assign(&h.wait()?);
                g_c.add_assign(&l.wait()?);

                Ok(Proof {
                    a: g_a.into_affine(),
                    b: g_b.into_affine(),
                    c: g_c.into_affine(),
                })
            },
        )
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    Ok(proofs)
}