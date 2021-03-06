use std::fs::{self, File, OpenOptions};
use std::io::prelude::*;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use bincode::{deserialize, serialize};
use log::{info/*, trace*/};
use memmap::MmapOptions;
use merkletree::merkle::MerkleTree;
use merkletree::store::{DiskStore, Store, StoreConfig};
use paired::bls12_381::{Bls12, Fr};
use storage_proofs::circuit::multi_proof::MultiProof;
use storage_proofs::circuit::stacked::StackedCompound;
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::drgraph::Graph;
use storage_proofs::hasher::{Domain, Hasher};
use storage_proofs::measurements::{measure_op, Operation::CommD};
use storage_proofs::merkle::create_merkle_tree;
use storage_proofs::proof::ProofScheme;
use storage_proofs::sector::SectorId;
use storage_proofs::stacked::{
    self, generate_replica_id, CacheKey, ChallengeRequirements, StackedDrg, Tau, TemporaryAux,
    TemporaryAuxCache,
};

use crate::api::util::{as_safe_commitment, commitment_from_fr, get_tree_leafs, get_tree_size};
use crate::caches::{get_stacked_params, get_stacked_verifying_key};
use crate::constants::{
    DefaultPieceHasher, DefaultTreeHasher, POREP_MINIMUM_CHALLENGES, SINGLE_PARTITION_PROOF_LEN,
};
use crate::parameters::setup_params;
pub use crate::pieces;
pub use crate::pieces::verify_pieces;
use crate::types::{
    Commitment, PaddedBytesAmount, PieceInfo, PoRepConfig, PoRepProofPartitions, ProverId,
    SealCommitOutput, SealCommitPhase1Output, SealPreCommitOutput, SealPreCommitPhase1Output,
    SectorSize, Ticket,
};

#[allow(clippy::too_many_arguments)]
pub fn seal_pre_commit_phase1<R, S, T>(
    porep_config: PoRepConfig,
    cache_path: R,
    in_path: S,
    out_path: T,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    piece_infos: &[PieceInfo],
) -> Result<SealPreCommitPhase1Output>
where
    R: AsRef<Path>,
    S: AsRef<Path>,
    T: AsRef<Path>,
{
    info!("seal_pre_commit_phase1: start");
    
    println!("seal_pre_commit_phase1: start");

    let sector_bytes = usize::from(PaddedBytesAmount::from(porep_config));
    println!("sector_bytes = {:?}",sector_bytes);


    fs::metadata(&in_path)
        .with_context(|| format!("could not read in_path={:?})", in_path.as_ref().display()))?;

    fs::metadata(&out_path)
        .with_context(|| format!("could not read out_path={:?}", out_path.as_ref().display()))?;

    println!("Copy unsealed data to output location = {:?}  to  {:?}",in_path.as_ref().display(),out_path.as_ref().display());
    // Copy unsealed data to output location, where it will be sealed in place.
    let copy_len = fs::copy(&in_path, &out_path).with_context(|| {
        format!(
            "could not copy in_path={:?} to out_path={:?}",
            in_path.as_ref().display(),
            out_path.as_ref().display()
        )
    })?;

    println!("total copyed bytes amout = {:?}",copy_len);

    println!("open out_path file for ...");
    let f_data = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&out_path)
        .with_context(|| format!("could not open out_path={:?}", out_path.as_ref().display()))?;

    // Zero-pad the data to the requested size by extending the underlying file if needed.
    f_data.set_len(sector_bytes as u64)?;
    println!("set out file len = {:?}",sector_bytes);

    println!("mmap file to var data ...");
    let data = unsafe {
        MmapOptions::new()
            .map_mut(&f_data)
            .with_context(|| format!("could not mmap out_path={:?}", out_path.as_ref().display()))?
    };

    println!("create setup & public params from porep_config ...");
    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        )?,
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
        priority: false,
    };
    println!("compound_setup_params = {:?}",compound_setup_params);
    let compound_public_params =
        <StackedCompound<DefaultTreeHasher, DefaultPieceHasher> as CompoundProof<
            _,
            StackedDrg<DefaultTreeHasher, DefaultPieceHasher>,
            _,
        >>::setup(&compound_setup_params)?;
    println!("compound_public_params = {:?}",compound_public_params);
    
    println!("building merkle tree for the original data");
    let (config, comm_d) = measure_op(CommD, || -> Result<_> {
        let tree_leafs =
            get_tree_leafs::<<DefaultPieceHasher as Hasher>::Domain>(porep_config.sector_size);
        ensure!(
            compound_public_params.vanilla_params.graph.size() == tree_leafs,
            "graph size and leaf size don't match"
        );

        println!(
            "seal phase 1: sector_size {}, tree size {}, tree leafs {}, cached above base {}",
            u64::from(porep_config.sector_size),
            get_tree_size::<<DefaultPieceHasher as Hasher>::Domain>(porep_config.sector_size),
            tree_leafs,
            StoreConfig::default_cached_above_base_layer(tree_leafs)
        );

        // MT for original data is always named tree-d, and it will be
        // referenced later in the process as such.
        let config = StoreConfig::new(
            cache_path.as_ref(),
            CacheKey::CommDTree.to_string(),
            StoreConfig::default_cached_above_base_layer(tree_leafs),
        );

        println!("StoreConfig = {:?}",config);

        let data_tree =
            create_merkle_tree::<DefaultPieceHasher>(Some(config.clone()), tree_leafs, &data)?;
        drop(data);

        println!("data_tree = {:?}",data_tree);

        let comm_d_root: Fr = data_tree.root().into();
        println!("comm_d_root = {:?}",comm_d_root);
        let comm_d = commitment_from_fr::<Bls12>(comm_d_root);
        println!("comm_d = {:?}",comm_d);
        drop(data_tree);

        Ok((config, comm_d))
    })?;

    info!("verifying pieces");

    ensure!(
        verify_pieces(&comm_d, piece_infos, porep_config.into())?,
        "pieces and comm_d do not match"
    );

    let replica_id =
        generate_replica_id::<DefaultTreeHasher, _>(&prover_id, sector_id.into(), &ticket, comm_d);
    println!("comm_d = {:?}",comm_d);
    println!("replica_id = {:?}",replica_id);

    let labels = StackedDrg::<DefaultTreeHasher, DefaultPieceHasher>::replicate_phase1(
        &compound_public_params.vanilla_params,
        &replica_id,
        config.clone(),
    )?;
    println!("labels = {:?}",labels);
   

    Ok(SealPreCommitPhase1Output {
        labels,
        config,
        comm_d,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn seal_pre_commit_phase2<R, S>(
    porep_config: PoRepConfig,
    phase1_output: SealPreCommitPhase1Output,
    cache_path: S,
    out_path: R,
) -> Result<SealPreCommitOutput>
where
    R: AsRef<Path>,
    S: AsRef<Path>,
{
    println!("seal_pre_commit_phase2: start");

    //获取第一阶段输出参数赋值到变量中
    /*
    第一阶段的输出结果看起来是这样的：
    SealPreCommitPhase1Output {
        labels: Labels {
            labels: [StoreConfig {
                path: "/tmp/.tmp3e7pDH",
                id: "layer-1",
                size: Some(32),
                levels: 2
            }],
            _h: PhantomData
        },
        config: StoreConfig {
            path: "/tmp/.tmp3e7pDH",
            id: "tree-d",
            size: None,
            levels: 2
        },
        comm_d: [12, 36, 188, 107, 36, 26, 232, 3, 61, 87, 197, 77, 79, 233, 212, 235, 30, 26, 4, 122, 77, 197, 133, 140, 175, 173, 199, 92, 228, 110, 56, 15]
    }
    */
    let SealPreCommitPhase1Output {
        mut labels,
        config,
        comm_d,
        ..
    } = phase1_output;


    //所有label的path设置为cache_path
    labels.update_root(cache_path.as_ref());

    //将磁盘文件映射到内存中
    let f_data = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&out_path)
        .with_context(|| format!("could not open out_path={:?}", out_path.as_ref().display()))?;
    let data = unsafe {
        MmapOptions::new()
            .map_mut(&f_data)
            .with_context(|| format!("could not mmap out_path={:?}", out_path.as_ref().display()))?
    };
    let data: storage_proofs::porep::Data<'_> = (data, PathBuf::from(out_path.as_ref())).into();

    // Load data tree from disk
    let data_tree = {
        let tree_size =
            get_tree_size::<<DefaultPieceHasher as Hasher>::Domain>(porep_config.sector_size);
        let tree_leafs =
            get_tree_leafs::<<DefaultPieceHasher as Hasher>::Domain>(porep_config.sector_size);

        println!(
            "seal phase 2: tree size {}, tree leafs {}, cached above base {}",
            tree_size,
            tree_leafs,
            StoreConfig::default_cached_above_base_layer(tree_leafs)
        );
        let config = StoreConfig::new(
            cache_path.as_ref(),
            CacheKey::CommDTree.to_string(),
            StoreConfig::default_cached_above_base_layer(tree_leafs),
        );
        println!("config used for tree_d = {:?}",config);
        //使用DefaultPieceHasher生成treed
        let store: DiskStore<<DefaultPieceHasher as Hasher>::Domain> =
            DiskStore::new_from_disk(tree_size, &config)?;
        MerkleTree::from_data_store(store, tree_leafs)
    }?;

    //treed is done

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        )?,
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
        priority: false,
    };
    println!("compound_setup_params = {:?}",compound_setup_params);
    let compound_public_params =
        <StackedCompound<DefaultTreeHasher, DefaultPieceHasher> as CompoundProof<
            _,
            StackedDrg<DefaultTreeHasher, DefaultPieceHasher>,
            _,
        >>::setup(&compound_setup_params)?;
    println!("compound_public_params = {:?}",compound_public_params);
    //TAU: 希腊字母，一棵或者多棵Merkle树的树根都称为TAU。AUX: Auxiliary的简称，一棵或者多棵Merkle树的结构称为AUX。
    //对于一层replica来说，TAU包括comm_d和comm_r，AUX包括tree_d和tree_r。
    let (tau, (p_aux, t_aux)) =
        StackedDrg::<DefaultTreeHasher, DefaultPieceHasher>::replicate_phase2(
            &compound_public_params.vanilla_params,
            labels,
            data,
            data_tree,
            config,
        )?;

    //得到复制处理后的root
    let comm_r = commitment_from_fr::<Bls12>(tau.comm_r.into());

    // Persist p_aux and t_aux here 存储
    let p_aux_path = cache_path.as_ref().join(CacheKey::PAux.to_string());
    let mut f_p_aux = File::create(&p_aux_path)
        .with_context(|| format!("could not create file p_aux={:?}", p_aux_path))?;
    let p_aux_bytes = serialize(&p_aux)?;
    f_p_aux
        .write_all(&p_aux_bytes)
        .with_context(|| format!("could not write to file p_aux={:?}", p_aux_path))?;

    let t_aux_path = cache_path.as_ref().join(CacheKey::TAux.to_string());
    let mut f_t_aux = File::create(&t_aux_path)
        .with_context(|| format!("could not create file t_aux={:?}", t_aux_path))?;
    let t_aux_bytes = serialize(&t_aux)?;
    f_t_aux
        .write_all(&t_aux_bytes)
        .with_context(|| format!("could not write to file t_aux={:?}", t_aux_path))?;

    Ok(SealPreCommitOutput { comm_r, comm_d })
}

#[allow(clippy::too_many_arguments)]
pub fn seal_commit_phase1<T: AsRef<Path>>(
    porep_config: PoRepConfig,
    cache_path: T,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
    pre_commit: SealPreCommitOutput,
    piece_infos: &[PieceInfo],
) -> Result<SealCommitPhase1Output> {
    println!("seal_commit_phase1:start");

    let SealPreCommitOutput { comm_d, comm_r } = pre_commit;

    ensure!(comm_d != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");
    ensure!(
        verify_pieces(&comm_d, piece_infos, porep_config.into())?,
        "pieces and comm_d do not match"
    );

    let p_aux = {
        let mut p_aux_bytes = vec![];
        let p_aux_path = cache_path.as_ref().join(CacheKey::PAux.to_string());
        let mut f_p_aux = File::open(&p_aux_path)
            .with_context(|| format!("could not open file p_aux={:?}", p_aux_path))?;
        f_p_aux.read_to_end(&mut p_aux_bytes)?;

        deserialize(&p_aux_bytes)
    }?;

    let t_aux = {
        let mut t_aux_bytes = vec![];
        let t_aux_path = cache_path.as_ref().join(CacheKey::TAux.to_string());
        let mut f_t_aux = File::open(&t_aux_path)
            .with_context(|| format!("could not open file t_aux={:?}", t_aux_path))?;
        f_t_aux.read_to_end(&mut t_aux_bytes)?;

        let mut res: TemporaryAux<_, _> = deserialize(&t_aux_bytes)?;

        // Switch t_aux to the passed in cache_path
        res.set_cache_path(cache_path);
        res
    };

    println!("read from disk to get p_aux,t_aux");

    // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
    // elements based on the configs stored in TemporaryAux.
    let t_aux_cache: TemporaryAuxCache<DefaultTreeHasher, DefaultPieceHasher> =
        TemporaryAuxCache::new(&t_aux).context("failed to restore contents of t_aux")?;

    let comm_r_safe = as_safe_commitment(&comm_r, "comm_r")?;
    let comm_d_safe = <DefaultPieceHasher as Hasher>::Domain::try_from_bytes(&comm_d)?;

    let sys_time = std::time::SystemTime::now();
    let replica_id = generate_replica_id::<DefaultTreeHasher, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d_safe,
    );
    println!("generate_replica_id duration = {:?}", std::time::SystemTime::now().duration_since(sys_time));

    println!("replica_id = {:?}",replica_id);

    let public_inputs = stacked::PublicInputs {
        replica_id,
        tau: Some(stacked::Tau {
            comm_d: comm_d_safe,
            comm_r: comm_r_safe,
        }),
        k: None,
        seed,
    };

    let private_inputs = stacked::PrivateInputs::<DefaultTreeHasher, DefaultPieceHasher> {
        p_aux,
        t_aux: t_aux_cache,
    };

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        )?,
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
        priority: false,
    };

    let compound_public_params =
        <StackedCompound<DefaultTreeHasher, DefaultPieceHasher> as CompoundProof<
            _,
            StackedDrg<DefaultTreeHasher, DefaultPieceHasher>,
            _,
        >>::setup(&compound_setup_params)?;

    println!("prepared private input,public input,setup params,public params.....");
    println!("prove_all_partitions");
    let vanilla_proofs = StackedDrg::prove_all_partitions(
        &compound_public_params.vanilla_params,
        &public_inputs,
        &private_inputs,
        StackedCompound::partition_count(&compound_public_params),
    )?;
    //println!("vanilla_proofs = {:?}",vanilla_proofs);

    println!("verify_all_partitions");
    let sanity_check = StackedDrg::verify_all_partitions(
        &compound_public_params.vanilla_params,
        &public_inputs,
        &vanilla_proofs,
    )?;
    ensure!(sanity_check, "Invalid vanilla proof generated");

    // Discard or compact cached MTs that are no longer needed.
   // println!("compact(t_aux) 0 = {:?}", &t_aux);
    TemporaryAux::<DefaultTreeHasher, DefaultPieceHasher>::compact(t_aux)?;
    //println!("compact(t_aux) = {:?}", &t_aux);

    println!("seal_commit_phase1:end");

    Ok(SealCommitPhase1Output {
        vanilla_proofs,
        comm_r,
        comm_d,
        replica_id,
        seed,
        ticket,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn seal_commit_phase2(
    porep_config: PoRepConfig,
    phase1_output: SealCommitPhase1Output,
    prover_id: ProverId,
    sector_id: SectorId,
) -> Result<SealCommitOutput> {
    info!("seal_commit_phase2:start");
    println!("seal_commit_phase2:start");
    let sys_time = std::time::SystemTime::now();


    let SealCommitPhase1Output {
        vanilla_proofs,
        comm_d,
        comm_r,
        replica_id,
        seed,
        ticket,
    } = phase1_output;

    ensure!(comm_d != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");

    println!("comm_r = {:?}",comm_r);
    let comm_r_safe = as_safe_commitment(&comm_r, "comm_r")?;
    println!("comm_r_safe = {:?}",comm_r_safe);
    println!("comm_d = {:?}",comm_d);
    let comm_d_safe = <DefaultPieceHasher as Hasher>::Domain::try_from_bytes(&comm_d)?;
    println!("comm_d_safe = {:?}",comm_d_safe);
    println!("PublicInputs:start");
    let public_inputs = stacked::PublicInputs {
        replica_id,
        tau: Some(stacked::Tau {
            comm_d: comm_d_safe,
            comm_r: comm_r_safe,
        }),
        k: None,
        seed,
    };
    println!("get_stacked_params:start");
    let groth_params = get_stacked_params(porep_config)?;
    //println!("groth_params = {:?}",groth_params);  很长
    println!(
        "got groth params ({}) while sealing",
        u64::from(PaddedBytesAmount::from(porep_config))
    );
    println!("SetupParams:start");
    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        )?,
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
        priority: false,
    };
    println!("compound_setup_params = {:?}",compound_setup_params);

    let compound_public_params =
        <StackedCompound<DefaultTreeHasher, DefaultPieceHasher> as CompoundProof<
            _,
            StackedDrg<DefaultTreeHasher, DefaultPieceHasher>,
            _,
        >>::setup(&compound_setup_params)?;
    println!("compound_public_params setup= {:?}",compound_public_params);

    println!("StackedCompound::circuit_proofs  :start");
    println!("Time Passed = {:?}", std::time::SystemTime::now().duration_since(sys_time));
    let groth_proofs = StackedCompound::circuit_proofs(
        &public_inputs,
        vanilla_proofs,
        &compound_public_params.vanilla_params,
        &groth_params,
        compound_public_params.priority,
    )?;   
    println!("groth_proofs = {:?}",groth_proofs);
    println!("StackedCompound::circuit_proofs  :finish");
    println!("Time Passed = {:?}", std::time::SystemTime::now().duration_since(sys_time));

    let proof = MultiProof::new(groth_proofs, &groth_params.vk);
    println!("MultiProof = {:?}",proof);
    let mut buf = Vec::with_capacity(
        SINGLE_PARTITION_PROOF_LEN * usize::from(PoRepProofPartitions::from(porep_config)),
    );
    println!("SINGLE_PARTITION_PROOF_LEN ={} Size = {:?}",SINGLE_PARTITION_PROOF_LEN,usize::from(PoRepProofPartitions::from(porep_config)));

    proof.write(&mut buf)?;
    println!("MultiProof buf = {:?}",buf);
    println!("Time Passed = {:?}", std::time::SystemTime::now().duration_since(sys_time));
    // Verification is cheap when parameters are cached,
    // and it is never correct to return a proof which does not verify.
    verify_seal(
        porep_config,
        comm_r,
        comm_d,
        prover_id,
        sector_id,
        ticket,
        seed,
        &buf,
    )
    .context("post-seal verification sanity check failed")?;

    println!("seal_commit_phase2:end");
    println!("Time Passed = {:?}", std::time::SystemTime::now().duration_since(sys_time));
    Ok(SealCommitOutput { proof: buf })
}

/// Computes a sectors's `comm_d` given its pieces.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in the sector.
/// * `piece_infos` - the piece info (commitment and byte length) for each piece in this sector.
pub fn compute_comm_d(sector_size: SectorSize, piece_infos: &[PieceInfo]) -> Result<Commitment> {
    pieces::compute_comm_d(sector_size, piece_infos)
}

/// Verifies the output of some previously-run seal operation.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in this sector.
/// * `comm_r_in` - commitment to the sector's replica (`comm_r`).
/// * `comm_d_in` - commitment to the sector's data (`comm_d`).
/// * `prover_id` - the prover-id that sealed this sector.
/// * `sector_id` - this sector's sector-id.
/// * `ticket` - the ticket that was used to generate this sector's replica-id.
/// * `seed` - the seed used to derive the porep challenges.
/// * `proof_vec` - the porep circuit proof serialized into a vector of bytes.
#[allow(clippy::too_many_arguments)]
pub fn verify_seal(
    porep_config: PoRepConfig,
    comm_r_in: Commitment,
    comm_d_in: Commitment,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
    proof_vec: &[u8],
) -> Result<bool> {

    println!("seal verify_seal start");

    ensure!(comm_d_in != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure!(comm_r_in != [0; 32], "Invalid all zero commitment (comm_r)");

    let sector_bytes = PaddedBytesAmount::from(porep_config);
    let comm_r = as_safe_commitment(&comm_r_in, "comm_r")?;
    let comm_d = as_safe_commitment(&comm_d_in, "comm_d")?;

    let replica_id =
        generate_replica_id::<DefaultTreeHasher, _>(&prover_id, sector_id.into(), &ticket, comm_d);

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        )?,
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
        priority: false,
    };

    let compound_public_params: compound_proof::PublicParams<
        '_,
        StackedDrg<'_, DefaultTreeHasher, DefaultPieceHasher>,
    > = StackedCompound::setup(&compound_setup_params)?;

    let public_inputs = stacked::PublicInputs::<
        <DefaultTreeHasher as Hasher>::Domain,
        <DefaultPieceHasher as Hasher>::Domain,
    > {
        replica_id,
        tau: Some(Tau { comm_r, comm_d }),
        seed,
        k: None,
    };

    let verifying_key = get_stacked_verifying_key(porep_config)?;
    println!("verifying_key = {:?}",verifying_key);

    println!(
        "got verifying key ({}) while verifying seal",
        u64::from(sector_bytes)
    );

    let partitioncount = usize::from(PoRepProofPartitions::from(porep_config));
    println!("partitioncount = {:?}",partitioncount);
    let proof = MultiProof::new_from_reader(
        Some(partitioncount),
        proof_vec,
        &verifying_key,
    )?;

    println!("StackedCompound::verify");


    StackedCompound::verify(
        &compound_public_params,
        &public_inputs,
        &proof,
        &ChallengeRequirements {
            minimum_challenges: *POREP_MINIMUM_CHALLENGES
                .read()
                .unwrap()
                .get(&u64::from(SectorSize::from(porep_config)))
                .expect("unknown sector size") as usize,
        },
    )
    .map_err(Into::into)
}

/// Verifies a batch of outputs of some previously-run seal operations.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in this sector.
/// * `[comm_r_ins]` - list of commitments to the sector's replica (`comm_r`).
/// * `[comm_d_ins]` - list of commitments to the sector's data (`comm_d`).
/// * `[prover_ids]` - list of prover-ids that sealed this sector.
/// * `[sector_ids]` - list of the sector's sector-id.
/// * `[tickets]` - list of tickets that was used to generate this sector's replica-id.
/// * `[seeds]` - list of seeds used to derive the porep challenges.
/// * `[proof_vecs]` - list of porep circuit proofs serialized into a vector of bytes.
#[allow(clippy::too_many_arguments)]
pub fn verify_batch_seal(
    porep_config: PoRepConfig,
    comm_r_ins: &[Commitment],
    comm_d_ins: &[Commitment],
    prover_ids: &[ProverId],
    sector_ids: &[SectorId],
    tickets: &[Ticket],
    seeds: &[Ticket],
    proof_vecs: &[&[u8]],
) -> Result<bool> {
    ensure!(!comm_r_ins.is_empty(), "Cannot prove empty batch");
    let l = comm_r_ins.len();
    ensure!(l == comm_d_ins.len(), "Inconsistent inputs");
    ensure!(l == prover_ids.len(), "Inconsistent inputs");
    ensure!(l == prover_ids.len(), "Inconsistent inputs");
    ensure!(l == sector_ids.len(), "Inconsistent inputs");
    ensure!(l == tickets.len(), "Inconsistent inputs");
    ensure!(l == seeds.len(), "Inconsistent inputs");
    ensure!(l == proof_vecs.len(), "Inconsistent inputs");

    for comm_d_in in comm_d_ins {
        ensure!(
            comm_d_in != &[0; 32],
            "Invalid all zero commitment (comm_d)"
        );
    }
    for comm_r_in in comm_r_ins {
        ensure!(
            comm_r_in != &[0; 32],
            "Invalid all zero commitment (comm_r)"
        );
    }

    let sector_bytes = PaddedBytesAmount::from(porep_config);

    let verifying_key = get_stacked_verifying_key(porep_config)?;
    info!(
        "got verifying key ({}) while verifying seal",
        u64::from(sector_bytes)
    );

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        )?,
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
        priority: false,
    };

    let compound_public_params: compound_proof::PublicParams<
        '_,
        StackedDrg<'_, DefaultTreeHasher, DefaultPieceHasher>,
    > = StackedCompound::setup(&compound_setup_params)?;

    let mut public_inputs = Vec::with_capacity(l);
    let mut proofs = Vec::with_capacity(l);

    for i in 0..l {
        let comm_r = as_safe_commitment(&comm_r_ins[i], "comm_r")?;
        let comm_d = as_safe_commitment(&comm_d_ins[i], "comm_d")?;

        let replica_id = generate_replica_id::<DefaultTreeHasher, _>(
            &prover_ids[i],
            sector_ids[i].into(),
            &tickets[i],
            comm_d,
        );

        public_inputs.push(stacked::PublicInputs::<
            <DefaultTreeHasher as Hasher>::Domain,
            <DefaultPieceHasher as Hasher>::Domain,
        > {
            replica_id,
            tau: Some(Tau { comm_r, comm_d }),
            seed: seeds[i],
            k: None,
        });
        proofs.push(MultiProof::new_from_reader(
            Some(usize::from(PoRepProofPartitions::from(porep_config))),
            proof_vecs[i],
            &verifying_key,
        )?);
    }

    StackedCompound::batch_verify(
        &compound_public_params,
        &public_inputs,
        &proofs,
        &ChallengeRequirements {
            minimum_challenges: *POREP_MINIMUM_CHALLENGES
                .read()
                .unwrap()
                .get(&u64::from(SectorSize::from(porep_config)))
                .expect("unknown sector size") as usize,
        },
    )
    .map_err(Into::into)
}
