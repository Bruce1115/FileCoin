
use super::*;

//use std::collections::BTreeMap;
use std::io::{Seek, SeekFrom, Write};
//use std::sync::Once;

//use ff::Field;
//use paired::bls12_381::{Bls12, Fr};
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
//use storage_proofs::election_post::Candidate;
//use storage_proofs::fr32::bytes_into_fr;
use tempfile::NamedTempFile;

use crate::constants::{POREP_PARTITIONS, SECTOR_SIZE_ONE_KIB/*, SINGLE_PARTITION_PROOF_LEN*/};
use crate::types::{/*PoStConfig, */SectorSize};


//use std::fs::File;
use std::io::{/*BufWriter, */Read/*, Seek, SeekFrom, Write*/};
//use std::path::{Path, PathBuf};

use anyhow::{/*anyhow, ensure, Context,*/ Result};
//use merkletree::store::StoreConfig;
//use storage_proofs::hasher::Hasher;
//use storage_proofs::porep::PoRep;
use storage_proofs::sector::SectorId;
//use storage_proofs::stacked::{generate_replica_id, CacheKey, StackedDrg};
//use tempfile::tempfile;

//use crate::api::util::{as_safe_commitment, get_tree_leafs};
//use crate::constants::{
   // DefaultPieceHasher, DefaultTreeHasher,
  //  MINIMUM_RESERVED_BYTES_FOR_PIECE_IN_FULLY_ALIGNED_SECTOR as MINIMUM_PIECE_SIZE,
//};
//use crate::fr32::{write_padded, write_unpadded};
//use crate::parameters::public_params;
//use crate::pieces::get_aligned_source;
use crate::types::{
    /*Commitment, */PaddedBytesAmount, /*PieceInfo, */PoRepConfig, PoRepProofPartitions,/* ProverId, */Ticket,
    UnpaddedByteIndex, UnpaddedBytesAmount,
};

pub use crate::api::post::*;
pub use crate::api::seal::*;
//pub use crate::api::common::*;
//use std::io;
//use storage_proofs::pieces::generate_piece_commitment_bytes_from_source;
pub const TEST_SEED: [u8; 16] = [
    0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5,
];


pub fn test_seal_lifecycle() -> Result<()> {
 
    println!();println!();println!();println!();
    let sys_time = std::time::SystemTime::now();

    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let sector_size =  SECTOR_SIZE_ONE_KIB; //SECTOR_SIZE_16_MIB;//;

    let number_of_bytes_in_piece =
        UnpaddedBytesAmount::from(PaddedBytesAmount(sector_size.clone()));

    println!("number_of_bytes_in_piece = {:?}   .0 ={:?}",number_of_bytes_in_piece,  number_of_bytes_in_piece.0);  
    //生成1K的随机数据，放在U8的vec中
    let piece_bytes: Vec<u8> = (0..number_of_bytes_in_piece.0)
                    //.map(|_| rand::random::<u8>())
       .map(|x| x as u8 %200 )
        .collect();

   // println!("piece_bytes = {:?}   length ={:?}",piece_bytes,  piece_bytes.len());        

    //将随机数写入到文件中
    let mut piece_file = NamedTempFile::new()?;
    piece_file.write_all(&piece_bytes)?;
    piece_file.as_file_mut().sync_all()?;
    piece_file.as_file_mut().seek(SeekFrom::Start(0))?;

    println!("write to piece_file = {:?}",piece_file); 

    //生成piece info
    let piece_info =
        generate_piece_commitment(piece_file.as_file_mut(), number_of_bytes_in_piece)?;
    piece_file.as_file_mut().seek(SeekFrom::Start(0))?;//继续回到开头

    println!("generate_piece_commitment = {:?}",piece_info); 

    let mut staged_sector_file = NamedTempFile::new()?;
    add_piece(
        &mut piece_file,
        &mut staged_sector_file,
        number_of_bytes_in_piece,
        &[],
    )?;

    println!("add_piece to staged_sector_file = {:?}",staged_sector_file); 

    println!("Time Passed = {:?}", std::time::SystemTime::now().duration_since(sys_time));

    let piece_infos = vec![piece_info];

    let sealed_sector_file = NamedTempFile::new()?;
    let mut unseal_file = NamedTempFile::new()?;
    let config = PoRepConfig {
        sector_size: SectorSize(sector_size.clone()),
        partitions: PoRepProofPartitions(
            *POREP_PARTITIONS.read().unwrap().get(&sector_size).unwrap(),
        ),
    };

    println!("PoRepConfig = {:?}",config); 

    let cache_dir = tempfile::tempdir().unwrap();
    let prover_id = rng.gen();
    let ticket: Ticket = rng.gen();
    let seed: Ticket = rng.gen();
    let sector_id = SectorId::from(12);
    println!();println!();println!();
    let phase1_output = seal_pre_commit_phase1(
        config,
        cache_dir.path(),
        staged_sector_file.path(),
        sealed_sector_file.path(),
        prover_id,
        sector_id,
        ticket,
        &piece_infos,
    )?;

    println!("seal_pre_commit_phase1 = {:?}",phase1_output); 
    println!("Time Passed After seal_pre_commit_phase1 = {:?}", std::time::SystemTime::now().duration_since(sys_time));
    println!();println!();println!();
    let pre_commit_output = seal_pre_commit_phase2(
        config,
        phase1_output,
        cache_dir.path(),
        sealed_sector_file.path(),
    )?;

    println!("seal_pre_commit_phase2_output = {:?}",pre_commit_output); 
    println!("Time Passed After seal_pre_commit_phase2 = {:?}", std::time::SystemTime::now().duration_since(sys_time));
    println!();println!();println!();

    let comm_d = pre_commit_output.comm_d.clone();
    let comm_r = pre_commit_output.comm_r.clone();

    let phase1_output = seal_commit_phase1(
        config,
        cache_dir.path(),
        prover_id,
        sector_id,
        ticket,
        seed,
        pre_commit_output,
        &piece_infos,
    )?;
   // println!("seal_commit_phase1_output = {:?}",phase1_output); 
    println!("Time Passed After seal_commit_phase1= {:?}", std::time::SystemTime::now().duration_since(sys_time));
    println!();println!();println!();

    let commit_output = seal_commit_phase2(config, phase1_output, prover_id, sector_id)?;

    println!("seal_commit_phase2_output = {:?}",commit_output); 
    println!("Time Passed After seal_commit_phase2= {:?}", std::time::SystemTime::now().duration_since(sys_time));

    let _ = get_unsealed_range(
        config,
        cache_dir.path(),
        &sealed_sector_file.path(),
        &unseal_file.path(),
        prover_id,
        sector_id,
        comm_d,
        ticket,
        UnpaddedByteIndex(508),
        UnpaddedBytesAmount(508),
    )?;

    println!("Time Passed After get_unsealed_range= {:?}", std::time::SystemTime::now().duration_since(sys_time));

    let mut contents = vec![];
    assert!(
        unseal_file.read_to_end(&mut contents).is_ok(),
        "failed to populate buffer with unsealed bytes"
    );
    assert_eq!(contents.len(), 508);
    assert_eq!(&piece_bytes[508..], &contents[..]);

    let computed_comm_d = compute_comm_d(config.sector_size, &piece_infos)?;

    assert_eq!(
        comm_d, computed_comm_d,
        "Computed and expected comm_d don't match."
    );

    let verified = verify_seal(
        config,
        comm_r,
        comm_d,
        prover_id,
        sector_id,
        ticket,
        seed,
        &commit_output.proof,
    )?;
    assert!(verified, "failed to verify valid seal");
    println!("verify_seal = {:?}",verified); 
    
    println!("Time Passed After verify_seal= {:?}", std::time::SystemTime::now().duration_since(sys_time));

    Ok(())
}
