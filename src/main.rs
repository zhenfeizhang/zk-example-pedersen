mod api;
mod pedersen;
mod r1cs;

use crate::api::*;
use algebra::ed_on_bls12_381::*;
use algebra::UniformRand;
use crypto_primitives::commitment::pedersen::Randomness;
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

    let zk_param = param_gen(param);
    let proof = proof_gen(&zk_param, circuit, &[0u8; 32]);
    assert!(verify(&zk_param, &proof, &commit))
}
