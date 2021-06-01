use ark_crypto_primitives::commitment::pedersen::Randomness;
use ark_ed_on_bls12_381::*;
use ark_ff::UniformRand;
use pedersen_example::*;

fn main() {
	let mut rng = ark_std::test_rng();
	let param = pedersen_setup(&[0u8; 32]);
	// input is a 256 bytes of vector
	let input = [
		"This is the input blob we want to commit to...".as_ref(),
		[0u8; 210].as_ref(),
	]
	.concat();
	let open = Randomness::<JubJub>(Fr::rand(&mut rng));
	let commit = pedersen_commit(input.as_ref(), &param, &open);

	let circuit = PedersenComCircuit {
		param: param.clone(),
		input: input.to_vec(),
		open,
		commit,
	};

	// check the circuit is satisfied
	sanity_check(circuit.clone());
	println!("circuit build");

	// generate the SRS for marlin proof system
	let (pk, vk) = marlin_param_gen(param);
	println!("keys generated");

	// generate the proof
	let proof = marlin_proof_gen(&pk, circuit, &[0u8; 32]);
	println!("proof generated");

	// verify the proof
	assert!(marlin_verify(&vk, &proof, &commit, &[0u8; 32]));
	println!("proof verified");
}
