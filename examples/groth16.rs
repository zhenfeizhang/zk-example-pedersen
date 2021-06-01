use ark_crypto_primitives::commitment::pedersen::Randomness;
use ark_ed_on_bls12_381::*;
use ark_ff::UniformRand;
use pedersen_example::*;

fn main() {
	let mut rng = ark_std::test_rng();

	// set up the proper inputs:
	//  commit = Pedersen(input, param, open)
	let param = pedersen_setup(&[0u8; 32]);

	// input is a 256 bytes of vector
	let input = [
		"This is the input blob we want to commit to...".as_ref(),
		[08; 210].as_ref(),
	]
	.concat();

	let open = Randomness::<JubJub>(Fr::rand(&mut rng));
	let commit = pedersen_commit(input.as_ref(), &param, &open);

	// build the input of the circuit
	let circuit = PedersenComCircuit {
		param: param.clone(),
		input: input.to_vec(),
		open,
		commit,
	};

	// check the circuit is satisfied
	assert!(sanity_check(circuit.clone()));

	// generate the CRS for Groth16
	let zk_param = groth_param_gen(param);

	// generate the proof
	let proof = groth_proof_gen(&zk_param, circuit, &[0u8; 32]);

	// verify the proof
	assert!(groth_verify(&zk_param, &proof, &commit));
}
