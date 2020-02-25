use crate::matrix::Matrix;
use crate::mds::{create_mds_matrices, factor_to_sparse_matrices, MDSMatrices};
use crate::preprocessing::compress_round_constants;
use crate::{matrix, quintic_s_box};
use crate::{round_constants, round_numbers, scalar_from_u64, Error};
use ff::{Field, ScalarEngine};
use generic_array::{sequence::GenericSequence, typenum, ArrayLength, GenericArray};
use std::marker::PhantomData;
use std::ops::Add;
use typenum::bit::B1;
use typenum::marker_traits::Unsigned;
use typenum::uint::{UInt, UTerm};
use typenum::{Add1, U2};

/// The arity tag is the first element of a Poseidon permutation.
/// This extra element is necessary for 128-bit security.
pub fn arity_tag<E: ScalarEngine, Arity: Unsigned>() -> E::Fr {
    scalar_from_u64::<E>((1 << Arity::to_usize()) - 1)
}

/// The `Poseidon` structure will accept a number of inputs equal to the arity.
#[derive(Debug, Clone, PartialEq)]
pub struct Poseidon<'a, E, Arity = U2>
where
    E: ScalarEngine,
    Arity: Unsigned + Add<B1> + Add<UInt<UTerm, B1>>,
    Add1<Arity>: ArrayLength<E::Fr>,
{
    constants_offset: usize,
    current_round: usize, // Used in static optimization only for now.
    /// the elements to permute
    pub elements: GenericArray<E::Fr, Add1<Arity>>,
    pos: usize,
    constants: &'a PoseidonConstants<E, Arity>,
    _e: PhantomData<E>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PoseidonConstants<E, Arity>
where
    E: ScalarEngine,
    Arity: Unsigned + Add<B1> + Add<UInt<UTerm, B1>>,
    Add1<Arity>: ArrayLength<E::Fr>,
{
    pub mds_matrices: MDSMatrices<E>,
    pub round_constants: Vec<E::Fr>,
    pub compressed_round_constants: Vec<E::Fr>,
    pub sparse_matrices: Vec<Matrix<E::Fr>>,
    pub arity_tag: E::Fr,
    pub full_rounds: usize,
    pub half_full_rounds: usize,
    pub partial_rounds: usize,
    _a: PhantomData<Arity>,
}

#[derive(Debug, PartialEq)]
pub enum HashMode {
    // The initial and correct version of the algorithm. We should preserve the ability to hash this way for reference
    // and to preserve confidence in our tests along thew way.
    Correct,
    // This mode is meant to be mostly synchronized with `Correct` but may reduce or simplify the total algorithm.
    // Its purpose is for use during refactoring/development, as a target for `ModB`.
    OptimizedDynamic,
    // Consumes statically pre-processed constants for simplest operation.
    OptimizedStatic,
}
use HashMode::{Correct, OptimizedDynamic, OptimizedStatic};

pub const DEFAULT_HASH_MODE: HashMode = Correct;

impl<'a, E, Arity> PoseidonConstants<E, Arity>
where
    E: ScalarEngine,
    Arity: Unsigned + Add<B1> + Add<UInt<UTerm, B1>>,
    Add1<Arity>: ArrayLength<E::Fr>,
{
    pub fn new() -> Self {
        let arity = Arity::to_usize();
        let width = arity + 1;

        let mds_matrices = create_mds_matrices::<E>(width);

        let (full_rounds, partial_rounds) = round_numbers(arity);
        let half_full_rounds = full_rounds / 2;
        let round_constants = round_constants::<E>(arity);
        let compressed_round_constants = compress_round_constants::<E>(
            width,
            full_rounds,
            partial_rounds,
            &round_constants,
            &mds_matrices,
            partial_rounds,
        );

        let sparse_matrices =
            factor_to_sparse_matrices::<E>(mds_matrices.m.clone(), partial_rounds);

        // Ensure we have enough constants for the sbox rounds
        assert!(
            width * (full_rounds + partial_rounds) <= round_constants.len(),
            "Not enough round constants"
        );

        assert_eq!(
            full_rounds * width + partial_rounds,
            compressed_round_constants.len()
        );

        Self {
            mds_matrices,
            round_constants,
            compressed_round_constants,
            sparse_matrices,
            arity_tag: arity_tag::<E, Arity>(),
            full_rounds,
            half_full_rounds,
            partial_rounds,
            _a: PhantomData::<Arity>,
        }
    }

    /// Returns the width.
    #[inline]
    pub fn arity(&self) -> usize {
        Arity::to_usize()
    }

    /// Returns the width.
    #[inline]
    pub fn width(&self) -> usize {
        Add1::<Arity>::to_usize()
    }
}

impl<'a, E, Arity> Poseidon<'a, E, Arity>
where
    E: ScalarEngine,
    Arity: Unsigned + Add<B1> + Add<UInt<UTerm, B1>>,
    Add1<Arity>: ArrayLength<E::Fr>,
{
    pub fn new(constants: &'a PoseidonConstants<E, Arity>) -> Self {
        let elements = GenericArray::generate(|i| {
            if i == 0 {
                constants.arity_tag
            } else {
                E::Fr::zero()
            }
        });
        Poseidon {
            constants_offset: 0,
            current_round: 0,
            elements,
            pos: 1,
            constants,
            _e: PhantomData::<E>,
        }
    }
    pub fn new_with_preimage(
        preimage: &[E::Fr],
        constants: &'a PoseidonConstants<E, Arity>,
    ) -> Self {
        assert_eq!(preimage.len(), Arity::to_usize(), "Invalid preimage size");

        let elements = GenericArray::generate(|i| {
            if i == 0 {
                constants.arity_tag
            } else {
                preimage[i - 1]
            }
        });

        let width = elements.len();

        Poseidon {
            constants_offset: 0,
            current_round: 0,
            elements,
            pos: width,
            constants,
            _e: PhantomData::<E>,
        }
    }

    /// Replace the elements with the provided optional items.
    ///
    /// # Panics
    ///
    /// Panics if the provided slice is bigger than the arity.
    pub fn set_preimage(&mut self, preimage: &[E::Fr]) {
        self.reset();
        self.elements[1..].copy_from_slice(&preimage);
    }

    /// Restore the initial state
    pub fn reset(&mut self) {
        self.constants_offset = 0;
        self.current_round = 0;
        self.elements[1..]
            .iter_mut()
            .for_each(|l| *l = scalar_from_u64::<E>(0u64));
        self.elements[0] = self.constants.arity_tag;
        self.pos = 1;
    }

    /// The returned `usize` represents the element position (within arity) for the input operation
    pub fn input(&mut self, element: E::Fr) -> Result<usize, Error> {
        // Cannot input more elements than the defined arity
        if self.pos >= self.constants.width() {
            return Err(Error::FullBuffer);
        }

        // Set current element, and increase the pointer
        self.elements[self.pos] = element;
        self.pos += 1;

        Ok(self.pos - 1)
    }

    pub fn hash_in_mode(&mut self, mode: HashMode) -> E::Fr {
        match mode {
            Correct => self.hash_correct(),
            OptimizedDynamic => self.hash_optimized_dynamic(),
            OptimizedStatic => self.hash_optimized_static(),
        }
    }

    pub fn hash(&mut self) -> E::Fr {
        self.hash_in_mode(DEFAULT_HASH_MODE)
    }

    /// The number of rounds is divided into two equal parts for the full rounds, plus the partial rounds.
    ///
    /// The returned element is the second poseidon element, the first is the arity tag.
    pub fn hash_correct(&mut self) -> E::Fr {
        // This counter is incremented when a round constants is read. Therefore, the round constants never
        // repeat
        // The first full round should use the initial constants.
        self.full_round();

        for _ in 1..self.constants.half_full_rounds {
            self.full_round();
        }

        // Constants were added in the previous full round, so skip them here (false argument).
        self.partial_round();

        for _ in 1..self.constants.partial_rounds {
            self.partial_round();
        }

        for _ in 0..self.constants.half_full_rounds {
            self.full_round();
        }

        self.elements[1]
    }

    pub fn hash_optimized_dynamic(&mut self) -> E::Fr {
        // The first full round should use the initial constants.
        self.full_round_dynamic(true, true);

        for _ in 1..(self.constants.half_full_rounds) {
            self.full_round_dynamic(false, true);
        }

        // Constants were added in the previous full round, so skip them here (false argument).
        self.partial_round_dynamic();

        for _ in 1..self.constants.partial_rounds {
            self.partial_round();
        }

        for _ in 0..self.constants.half_full_rounds {
            self.full_round_dynamic(true, false);
        }

        self.elements[1]
    }

    pub fn hash_optimized_static(&mut self) -> E::Fr {
        // The first full round should use the initial constants.
        self.add_round_constants_static();

        for _ in 0..self.constants.half_full_rounds {
            self.full_round_static(false);
        }

        for _ in 0..self.constants.partial_rounds {
            self.partial_round_static();
        }

        // All but last full round.
        for _ in 1..self.constants.half_full_rounds {
            self.full_round_static(false);
        }
        self.full_round_static(true);

        assert_eq!(
            self.constants_offset,
            self.constants.compressed_round_constants.len(),
            "Constants consumed ({}) must equal preprocessed constants provided ({}).",
            self.constants_offset,
            self.constants.compressed_round_constants.len()
        );

        self.elements[1]
    }

    pub fn full_round(&mut self) {
        // NOTE: decrease in performance is expected during this refactoring.
        // We seek to preserve correctness while transforming the algorithm to an eventually more performant one.

        // Apply the quintic S-Box to all elements, after adding the round key.
        // Round keys are added in the S-box to match circuits (where the addition is free)
        // and in preparation for the shift to adding round keys after (rather than before) applying the S-box.

        let pre_round_keys = self
            .constants
            .round_constants
            .iter()
            .skip(self.constants_offset)
            .map(|x| Some(x));

        self.elements
            .iter_mut()
            .zip(pre_round_keys)
            .for_each(|(l, pre)| {
                quintic_s_box::<E>(l, pre, None);
            });

        self.constants_offset += self.elements.len();

        // M(B)
        // Multiply the elements by the constant MDS matrix
        self.product_mds();
    }

    pub fn full_round_dynamic(
        &mut self,
        add_current_round_keys: bool,
        absorb_next_round_keys: bool,
    ) {
        // NOTE: decrease in performance is expected when using this pathway.
        // We seek to preserve correctness while transforming the algorithm to an eventually more performant one.

        // Round keys are added in the S-box to match circuits (where the addition is free).
        // If requested, add round keys synthesized from following round after (rather than before) applying the S-box.
        let pre_round_keys = self
            .constants
            .round_constants
            .iter()
            .skip(self.constants_offset)
            .map(|x| {
                if add_current_round_keys {
                    Some(x)
                } else {
                    None
                }
            });

        if absorb_next_round_keys {
            // Using the notation from `test_inverse` in matrix.rs:
            // S
            let post_vec = self
                .constants
                .round_constants
                .iter()
                .skip(
                    self.constants_offset
                        + if add_current_round_keys {
                            self.elements.len()
                        } else {
                            0
                        },
                )
                .take(self.elements.len())
                .map(|x| *x)
                .collect::<Vec<_>>();

            // Compute the constants which should be added *before* the next `product_mds`.
            // in order to have the same effect as adding the given constants *after* the next `product_mds`.

            // M^-1(S)
            let inverted_vec =
                matrix::apply_matrix::<E>(&self.constants.mds_matrices.m_inv, &post_vec);

            // M(M^-1(S))
            let original = matrix::apply_matrix::<E>(&self.constants.mds_matrices.m, &inverted_vec);

            // S = M(M^-1(S))
            assert_eq!(&post_vec, &original, "Oh no, the inversion trick failed.");

            let post_round_keys = inverted_vec.iter();

            // S-Box Output = B.
            // With post-add, result is B + M^-1(S).
            self.elements
                .iter_mut()
                .zip(pre_round_keys.zip(post_round_keys))
                .for_each(|(l, (pre, post))| {
                    quintic_s_box::<E>(l, pre, Some(post));
                });
        } else {
            self.elements
                .iter_mut()
                .zip(pre_round_keys)
                .for_each(|(l, pre)| {
                    quintic_s_box::<E>(l, pre, None);
                });
        }
        let mut consumed = 0;
        if add_current_round_keys {
            consumed += self.elements.len()
        };
        if absorb_next_round_keys {
            consumed += self.elements.len()
        };
        self.constants_offset += consumed;

        // If absorb_next_round_keys
        //   M(B + M^-1(S)
        // else
        //   M(B)
        // Multiply the elements by the constant MDS matrix
        self.product_mds();
    }

    fn full_round_static(&mut self, last_round: bool) {
        let to_take = self.elements.len();
        let post_round_keys = self
            .constants
            .compressed_round_constants
            .iter()
            .skip(self.constants_offset)
            .take(to_take);

        if !last_round {
            let needed = self.constants_offset + to_take;
            assert!(
                needed <= self.constants.compressed_round_constants.len(),
                "Not enough preprocessed round constants ({}), need {}.",
                self.constants.compressed_round_constants.len(),
                needed
            );
        }
        self.elements
            .iter_mut()
            .zip(post_round_keys)
            .for_each(|(l, post)| {
                // Be explicit that no round key is added after last round of S-boxes.
                let post_key = if last_round {
                    panic!("Trying to skip last full round, but there is a key here! ({})");
                } else {
                    Some(post)
                };
                quintic_s_box::<E>(l, None, post_key);
            });
        // We need this because post_round_keys will have been empty, so it didn't happen in the for_each. :(
        if last_round {
            self.elements
                .iter_mut()
                .for_each(|l| quintic_s_box::<E>(l, None, None));
        } else {
            self.constants_offset += self.elements.len();
        }
        self.product_mds_static();
    }

    /// The partial round is the same as the full round, with the difference that we apply the S-Box only to the first bitflags poseidon leaf.
    pub fn partial_round(&mut self) {
        // Every element of the hash buffer is incremented by the round constants
        self.add_round_constants();

        // Apply the quintic S-Box to the first element
        quintic_s_box::<E>(&mut self.elements[0], None, None);

        // Multiply the elements by the constant MDS matrix
        self.product_mds();
    }

    pub fn partial_round_dynamic(&mut self) {
        // Apply the quintic S-Box to the first element
        quintic_s_box::<E>(&mut self.elements[0], None, None);

        // Multiply the elements by the constant MDS matrix
        self.product_mds();
    }

    /// The partial round is the same as the full round, with the difference that we apply the S-Box only to the first (arity tag) poseidon leaf.
    fn partial_round_static(&mut self) {
        let post_round_key = self.constants.compressed_round_constants[self.constants_offset];

        // Apply the quintic S-Box to the first element
        quintic_s_box::<E>(&mut self.elements[0], None, Some(&post_round_key));
        self.constants_offset += 1;

        self.product_mds_static();
    }

    /// For every leaf, add the round constants with index defined by the constants offset, and increment the
    /// offset
    fn add_round_constants(&mut self) {
        for (element, round_constant) in self.elements.iter_mut().zip(
            self.constants
                .round_constants
                .iter()
                .skip(self.constants_offset),
        ) {
            element.add_assign(round_constant);
        }

        self.constants_offset += self.elements.len();
    }

    fn add_round_constants_static(&mut self) {
        for (element, round_constant) in self.elements.iter_mut().zip(
            self.constants
                .compressed_round_constants
                .iter()
                .skip(self.constants_offset),
        ) {
            element.add_assign(round_constant);
        }

        self.constants_offset += self.elements.len();
    }

    /// Set the provided elements with the result of the product between the elements and the constant
    /// MDS matrix.
    fn product_mds(&mut self) {
        self.product_mds_with_matrix(&self.constants.mds_matrices.m);
    }

    /// Set the provided elements with the result of the product between the elements and the appropriate
    /// MDS matrix.
    fn product_mds_static(&mut self) {
        let full_half = self.constants.half_full_rounds;
        let sparse_offset = full_half - 1;
        if self.current_round == sparse_offset {
            // FIXME: the first matrix is not sparse. It shouldn't be in sparse_matrices.
            self.product_mds_with_matrix(&self.constants.sparse_matrices[0]);
        } else {
            if (self.current_round > sparse_offset)
                && (self.current_round < full_half + self.constants.partial_rounds)
            {
                let index = self.current_round - sparse_offset;
                let sparse_matrix = &self.constants.sparse_matrices[index];

                self.product_mds_with_sparse_matrix(&sparse_matrix);
            //self.product_mds_with_matrix(&sparse_matrix);
            } else {
                self.product_mds();
            }
        };

        self.current_round += 1;
    }

    fn product_mds_with_matrix(&mut self, matrix: &Matrix<E::Fr>) {
        let mut result = GenericArray::<E::Fr, Add1<Arity>>::generate(|_| E::Fr::zero());

        for (j, val) in result.iter_mut().enumerate() {
            for (i, row) in matrix.iter().enumerate() {
                let mut tmp = row[j];
                tmp.mul_assign(&self.elements[i]);
                val.add_assign(&tmp);
            }
        }

        std::mem::replace(&mut self.elements, result);
    }

    // Sparse matrix in this context means one of the form, M''.
    fn product_mds_with_sparse_matrix(&mut self, matrix: &Matrix<E::Fr>) {
        let mut result = GenericArray::<E::Fr, Add1<Arity>>::generate(|_| E::Fr::zero());

        // First column is dense.
        for (i, row) in matrix.iter().enumerate() {
            let mut tmp = row[0];
            tmp.mul_assign(&self.elements[i]);
            result[0].add_assign(&tmp);
        }

        for (j, val) in result.iter_mut().enumerate().skip(1) {
            // Except for first row/column, diagonals are one.
            val.add_assign(&self.elements[j]);

            // First row is dense.
            let mut tmp = matrix[0][j];
            tmp.mul_assign(&self.elements[0]);
            val.add_assign(&tmp);
        }

        std::mem::replace(&mut self.elements, result);
    }

    fn debug(&self, msg: &str) {
        dbg!(msg, &self.constants_offset, &self.elements);
    }
}

/// Poseidon convenience hash function.
/// NOTE: this is expensive, since it computes all constants when initializing hasher struct.
pub fn poseidon<E, Arity>(preimage: &[E::Fr]) -> E::Fr
where
    E: ScalarEngine,
    Arity: Unsigned + Add<B1> + Add<UInt<UTerm, B1>>,
    Add1<Arity>: ArrayLength<E::Fr>,
{
    let constants = PoseidonConstants::<E, Arity>::new();
    Poseidon::<E, Arity>::new_with_preimage(preimage, &constants).hash()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use ff::Field;
    use generic_array::typenum::{U11, U2, U4, U8};
    use paired::bls12_381::Bls12;
    use std::time::{*};


    #[test]
    #[ignore]
    fn reset() {
        let test_arity = 2;
        let preimage = vec![Scalar::one(); test_arity];
        let constants = PoseidonConstants::new();
        let mut h = Poseidon::<Bls12, U2>::new_with_preimage(&preimage, &constants);
        h.hash();
        h.reset();

        let default = Poseidon::<Bls12, U2>::new(&constants);
        assert_eq!(default.pos, h.pos);
        assert_eq!(default.elements, h.elements);
        assert_eq!(default.constants_offset, h.constants_offset);
    }

    #[test]
    fn hash_det() {
        let test_arity = 7;
        let mut preimage = vec![Scalar::zero(); test_arity];
        let constants = PoseidonConstants::new();
        preimage[0] = Scalar::one();


        let start = SystemTime::now();

        let mut h = Poseidon::<Bls12, typenum::consts::U7>::new_with_preimage(&preimage, &constants);
        println!("preimage= {:?}",preimage);
      //  println!("constants= :{:?}",constants);
        println!("Poseidon new_with_preimage duration {:?}",SystemTime::now().duration_since(start));

        let start2 = SystemTime::now();
        let mut h2 = h.clone();
        let result: <Bls12 as ScalarEngine>::Fr = h.hash();
        println!("Poseidon  duration:{:?}",SystemTime::now().duration_since(start2));
        println!("result= :{:?}",result);

        
        assert_eq!(result, h2.hash());
    }

    #[test]
    #[ignore]
    fn hash_arity_3() {
        let mut preimage: [Scalar; 3] = [Scalar::zero(); 3];
        let constants = PoseidonConstants::new();
        preimage[0] = Scalar::one();

        let mut h = Poseidon::<Bls12, typenum::U3>::new_with_preimage(&preimage, &constants);

        let mut h2 = h.clone();
        let result: <Bls12 as ScalarEngine>::Fr = h.hash();

        assert_eq!(result, h2.hash());
    }

    #[test]
    #[ignore]
    fn hash_values() {
        hash_values_aux::<U2>();
        hash_values_aux::<U4>();
        hash_values_aux::<U8>();
        hash_values_aux::<U11>();
    }

    /// Simple test vectors to ensure results don't change unintentionally in development.
    fn hash_values_aux<Arity>()
    where
        Arity: Unsigned + Add<B1> + Add<UInt<UTerm, B1>>,
        Add1<Arity>: ArrayLength<<Bls12 as ScalarEngine>::Fr>,
    {
        // NOTE: For now, type parameters on constants, p, and in the final assertion below need to be updated manually when testing different arities.
        // TODO: Mechanism to run all tests every time. (Previously only a single arity was compiled in.)
        let constants = PoseidonConstants::<Bls12, Arity>::new();
        let mut p = Poseidon::<Bls12, Arity>::new(&constants);
        let mut p2 = Poseidon::<Bls12, Arity>::new(&constants);
        let mut p3 = Poseidon::<Bls12, Arity>::new(&constants);
        let mut p4 = Poseidon::<Bls12, Arity>::new(&constants);

        let test_arity = constants.arity();
        let mut preimage = vec![Scalar::zero(); test_arity];
        for n in 0..test_arity {
            let scalar = scalar_from_u64::<Bls12>(n as u64);
            p.input(scalar).unwrap();
            p2.input(scalar).unwrap();
            p3.input(scalar).unwrap();
            p4.input(scalar).unwrap();

            preimage[n] = scalar;
        }

        let digest = p.hash();
        let digest2 = p2.hash_in_mode(Correct);
        let digest3 = p3.hash_in_mode(OptimizedStatic);
        let digest4 = p4.hash_in_mode(OptimizedDynamic);
        assert_eq!(digest, digest2);
        assert_eq!(digest, digest3);
        assert_eq!(digest, digest4);

        let expected = match test_arity {
            2 => scalar_from_u64s([
                0x7179d3495ac25e92,
                0x81052897659f7762,
                0x316a6d20e4a55d6c,
                0x409e8342edab687b,
            ]),
            4 => scalar_from_u64s([
                0xf53a7d58aacf0621,
                0x42d3a014639efdcf,
                0xe1a3fddb08c13a46,
                0x43f94dbd0abd1c99,
            ]),
            8 => scalar_from_u64s([
                0xa6a3e7a6b2cc7b85,
                0xfb1eb8f641dd9dc3,
                0xfd2a373272ebf604,
                0x433c1e9e8de226e5,
            ]),

            11 => scalar_from_u64s([
                0x3ea151bdba419d91,
                0x861e5b917b9025aa,
                0xfbd9089c1dda8c8a,
                0x229f5e566b78ee21,
            ]),
            _ => {
                dbg!(digest);
                panic!("Arity lacks test vector: {}", test_arity)
            }
        };
        dbg!(test_arity);
        assert_eq!(expected, digest);

        assert_eq!(
            digest,
            poseidon::<Bls12, Arity>(&preimage),
            "Poseidon wrapper disagrees with element-at-a-time invocation."
        );
    }

    #[test]
    #[ignore]
    fn hash_compare_optimized() {
        // NOTE: For now, type parameters on constants, p, and in the final assertion below need to be updated manually when testing different arities.
        // TODO: Mechanism to run all tests every time. (Previously only a single arity was compiled in.)
        let constants = PoseidonConstants::<Bls12, U2>::new();
        let mut p = Poseidon::<Bls12, U2>::new(&constants);
        let test_arity = constants.arity();
        let mut preimage = vec![Scalar::zero(); test_arity];
        for n in 0..test_arity {
            let scalar = scalar_from_u64::<Bls12>(n as u64);
            p.input(scalar).unwrap();
            preimage[n] = scalar;
        }
        let mut p2 = p.clone();
        let mut p3 = p.clone();

        let digest_correct = p.hash_in_mode(Correct);

        let digest_optimized_dynamic = p2.hash_in_mode(OptimizedDynamic);
        let digest_optimized_static = p3.hash_in_mode(OptimizedStatic);

        assert_eq!(digest_correct, digest_optimized_dynamic);
        assert_eq!(digest_correct, digest_optimized_static);
    }
}
