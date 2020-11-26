use crate::pedersen::*;
use crate::r1cs::*;
use algebra::ed_on_bls12_381::Fq;
use algebra::ed_on_bls12_381::Fr;
use algebra::UniformRand;
use crypto_primitives::commitment::pedersen::Randomness;
use groth16::*;
use r1cs_core::ConstraintSynthesizer;
use r1cs_core::ConstraintSystem;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

pub fn sanity_check() -> bool {
    let mut rng = rand::thread_rng();
    let len = 256;
    let param = setup(&[0u8; 32]);
    let input = vec![0u8; len];
    let open = Randomness::<JubJub>(Fr::rand(&mut rng));
    let commit = pedersen_commit(&input, &param, &open);

    let circuit = PedersenComCircuit {
        param,
        input,
        open,
        commit,
    };
    // sanity checks
    let sanity_cs = ConstraintSystem::<Fq>::new_ref();
    circuit.generate_constraints(sanity_cs.clone()).unwrap();
    let res = sanity_cs.is_satisfied().unwrap();

    #[cfg(debug_assertions)]
    {
        println!("are the constraints satisfied?: {}\n", res);
        println!(
            "number of constraint {} for data size: {}\n",
            sanity_cs.num_constraints(),
            len
        );
    }
    if !res {
        println!(
            "{:?} {} {:#?}",
            sanity_cs.constraint_names(),
            sanity_cs.num_constraints(),
            sanity_cs.which_is_unsatisfied().unwrap()
        );
    }
    res
}

pub fn param_gen(
    param: PedersenParam,
) -> Parameters<algebra::bls12::Bls12<algebra::bls12_381::Parameters>> {
    let mut rng = rand::thread_rng();
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
    generate_random_parameters::<algebra::Bls12_381, _, _>(circuit, &mut rng).unwrap()
}

pub fn proof_gen(
    param: &Parameters<algebra::bls12::Bls12<algebra::bls12_381::Parameters>>,
    circuit: PedersenComCircuit,
    seed: &[u8; 32],
) -> Proof<algebra::bls12::Bls12<algebra::bls12_381::Parameters>> {
    let mut rng = ChaCha20Rng::from_seed(*seed);
    create_random_proof(circuit, &param, &mut rng).unwrap()
}

pub fn verify(
    param: &Parameters<algebra::bls12::Bls12<algebra::bls12_381::Parameters>>,
    proof: &Proof<algebra::bls12::Bls12<algebra::bls12_381::Parameters>>,
    commit: &PedersenCommitment,
) -> bool {
    let pvk = prepare_verifying_key(&param.vk);
    let inputs = [commit.x, commit.y];
    verify_proof(&pvk, &proof, &inputs[..]).unwrap()
}
