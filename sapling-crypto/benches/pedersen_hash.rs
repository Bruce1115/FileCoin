#![feature(test)]

extern crate fil_sapling_crypto;
extern crate paired;
extern crate rand;
extern crate test;

use fil_sapling_crypto::jubjub::JubjubBls12;
use fil_sapling_crypto::pedersen_hash::{pedersen_hash, Personalization};
use paired::bls12_381::Bls12;
use rand::{thread_rng, Rng};

fn bench_pedersen_hash_aux(b: &mut test::Bencher, params: JubjubBls12, num_bytes: usize) {
    let rng = &mut thread_rng();
    let bits = (0..num_bytes * 8).map(|_| rng.gen()).collect::<Vec<_>>();
    let personalization = Personalization::None;

    b.bytes = num_bytes as u64;
    b.iter(|| pedersen_hash::<Bls12, _>(personalization, bits.clone(), &params));
}

#[cfg(target_arch = "x86_64")]
fn bench_pedersen_hash_precomp_aux(b: &mut test::Bencher, params: JubjubBls12, num_bytes: usize) {
    use fil_sapling_crypto::pedersen_hash::pedersen_hash_bls12_381_with_precomp;

    let rng = &mut thread_rng();
    let bits = (0..num_bytes * 8).map(|_| rng.gen()).collect::<Vec<_>>();
    let personalization = Personalization::None;

    b.bytes = num_bytes as u64;
    b.iter(|| pedersen_hash_bls12_381_with_precomp::<_>(personalization, bits.clone(), &params));
}

#[bench]
fn bench_pedersen_hash_32(b: &mut test::Bencher) {
    let params = JubjubBls12::new();
    bench_pedersen_hash_aux(b, params, 32);
}

#[bench]
fn bench_pedersen_hash_w16_32(b: &mut test::Bencher) {
    let params = JubjubBls12::new_with_window_size(16);
    bench_pedersen_hash_aux(b, params, 32);
}

#[bench]
fn bench_pedersen_hash_w17_32(b: &mut test::Bencher) {
    let params = JubjubBls12::new_with_window_size(17);
    bench_pedersen_hash_aux(b, params, 32);
}

#[bench]
fn bench_pedersen_hash_w18_32(b: &mut test::Bencher) {
    let params = JubjubBls12::new_with_window_size(18);
    bench_pedersen_hash_aux(b, params, 32);
}

#[bench]
fn bench_pedersen_hash_w19_32(b: &mut test::Bencher) {
    let params = JubjubBls12::new_with_window_size(19);
    bench_pedersen_hash_aux(b, params, 32);
}

#[cfg(target_arch = "x86_64")]
#[bench]
fn bench_pedersen_hash_using_precomp_32(b: &mut test::Bencher) {
    let params = JubjubBls12::new();
    bench_pedersen_hash_precomp_aux(b, params, 32);
}

#[cfg(target_arch = "x86_64")]
#[bench]
fn bench_pedersen_hash_using_precomp_w16_32(b: &mut test::Bencher) {
    let params = JubjubBls12::new_with_window_size(16);
    bench_pedersen_hash_precomp_aux(b, params, 32);
}

#[cfg(target_arch = "x86_64")]
#[bench]
fn bench_pedersen_hash_using_precomp_w17_32(b: &mut test::Bencher) {
    let params = JubjubBls12::new_with_window_size(17);
    bench_pedersen_hash_precomp_aux(b, params, 32);
}

#[cfg(target_arch = "x86_64")]
#[bench]
fn bench_pedersen_hash_using_precomp_w18_32(b: &mut test::Bencher) {
    let params = JubjubBls12::new_with_window_size(18);
    bench_pedersen_hash_precomp_aux(b, params, 32);
}

#[cfg(target_arch = "x86_64")]
#[bench]
fn bench_pedersen_hash_using_precomp_w19_32(b: &mut test::Bencher) {
    let params = JubjubBls12::new_with_window_size(19);
    bench_pedersen_hash_precomp_aux(b, params, 32);
}

#[bench]
fn bench_pedersen_hash_w16_64(b: &mut test::Bencher) {
    let params = JubjubBls12::new_with_window_size(16);
    bench_pedersen_hash_aux(b, params, 64);
}

#[cfg(target_arch = "x86_64")]
#[bench]
fn bench_pedersen_hash_using_precomp_w16_64(b: &mut test::Bencher) {
    let params = JubjubBls12::new_with_window_size(16);
    bench_pedersen_hash_precomp_aux(b, params, 64);
}
