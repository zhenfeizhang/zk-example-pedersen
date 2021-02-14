mod groth_api;
mod pedersen;
mod r1cs;
mod marlin;

use ark_crypto_primitives::commitment::pedersen::Randomness;
use ark_ed_on_bls12_381::*;
use ark_ff::UniformRand;
use groth_api::*;
use pedersen::*;
use r1cs::*;

fn main() {
    let mut rng = rand::thread_rng();
    let len = 256;
    let param = setup(&[0u8; 32]);
    let input = vec![0u8; len];
    let open = Randomness::<JubJub>(Fr::rand(&mut rng));
    let commit = pedersen_commit(&input, &param, &open);

    let circuit = PedersenComCircuit {
        param: param.clone(),
        input,
        open,
        commit,
    };

    sanity_check();

    let zk_param = groth_param_gen(param);
    let proof = groth_proof_gen(&zk_param, circuit, &[0u8; 32]);
    assert!(groth_verify(&zk_param, &proof, &commit))
}
