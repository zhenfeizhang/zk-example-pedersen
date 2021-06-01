use crate::{pedersen::*, r1cs::*};
use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::commitment::pedersen::Randomness;
use ark_ed_on_bls12_381::{Fq, Fr};
use ark_ff::UniformRand;
use ark_marlin::{ahp::AHPForR1CS, *};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::{rand::SeedableRng, vec};
use blake2::Blake2s;
use rand_chacha::ChaCha20Rng;

#[cfg(debug_assertions)]
use ark_poly_commit::PCUniversalParams;
#[cfg(debug_assertions)]
use ark_std::println;

pub type MultiPC = MarlinKZG10<Bls12_381, DensePolynomial<Fq>>;
pub type MarlinInst = Marlin<Fq, MultiPC, Blake2s>;

pub fn marlin_param_gen(
	param: PedersenParam,
) -> (IndexProverKey<Fq, MultiPC>, IndexVerifierKey<Fq, MultiPC>) {
	let mut rng = ark_std::test_rng();
	let len = 256;
	let input = vec![0u8; len];
	let open = Randomness::<JubJub>(Fr::rand(&mut rng));
	let commit = pedersen_commit(&input, &param, &open);

	let circuit = PedersenComCircuit {
		param,
		input,
		open,
		commit,
	};
	let sanity_cs = ConstraintSystem::<Fq>::new_ref();
	circuit
		.clone()
		.generate_constraints(sanity_cs.clone())
		.unwrap();

	let no_cs = sanity_cs.num_constraints();
	let no_var = sanity_cs.num_witness_variables();
	let _no_non_zero = sanity_cs.num_instance_variables();

	#[cfg(debug_assertions)]
	println!("inputs {} {} {}", no_cs, no_var, _no_non_zero);

	let _index = AHPForR1CS::index(circuit.clone()).unwrap();

	#[cfg(debug_assertions)]
	println!("index {}", _index.max_degree());

	type MultiPC = MarlinKZG10<Bls12_381, DensePolynomial<Fq>>;
	type MarlinInst = Marlin<Fq, MultiPC, Blake2s>;

	let srs = MarlinInst::universal_setup(no_cs, no_var * 2, 0, &mut rng).unwrap();

	#[cfg(debug_assertions)]
	{
		println!("srs generated");
		println!(
			"srs max degree: {}, index degree {}",
			srs.max_degree(),
			_index.max_degree()
		);
	}
	let (pk, vk) = MarlinInst::index(&srs, circuit).unwrap();

	(pk, vk)
}

pub fn marlin_proof_gen(
	param: &IndexProverKey<Fq, MultiPC>,
	circuit: PedersenComCircuit,
	seed: &[u8; 32],
) -> ark_marlin::Proof<Fq, MultiPC> {
	let mut rng = ChaCha20Rng::from_seed(*seed);
	MarlinInst::prove(&param, circuit, &mut rng).unwrap()
}

pub fn marlin_verify(
	param: &IndexVerifierKey<Fq, MultiPC>,
	proof: &ark_marlin::Proof<Fq, MultiPC>,
	commit: &PedersenCommitment,
	seed: &[u8; 32],
) -> bool {
	let mut rng = ChaCha20Rng::from_seed(*seed);
	MarlinInst::verify(&param, &[commit.x, commit.y], &proof, &mut rng).unwrap()
}
