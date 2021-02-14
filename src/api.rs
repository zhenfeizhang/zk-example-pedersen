use crate::pedersen::*;
use crate::r1cs::*;
use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::commitment::pedersen::Randomness;
use ark_crypto_primitives::SNARK;
use ark_ed_on_bls12_381::Fq;
use ark_ed_on_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_groth16::*;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_relations::r1cs::ConstraintSystem;
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

pub fn groth_param_gen(param: PedersenParam) -> <Groth16<Bls12_381> as SNARK<Fq>>::ProvingKey {
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
    generate_random_parameters::<Bls12_381, _, _>(circuit, &mut rng).unwrap()
}

pub fn groth_proof_gen(
    param: &<Groth16<Bls12_381> as SNARK<Fq>>::ProvingKey,
    circuit: PedersenComCircuit,
    seed: &[u8; 32],
) -> <Groth16<Bls12_381> as SNARK<Fq>>::Proof {
    let mut rng = ChaCha20Rng::from_seed(*seed);
    create_random_proof(circuit, &param, &mut rng).unwrap()
}

pub fn groth_verify(
    param: &<Groth16<Bls12_381> as SNARK<Fq>>::ProvingKey,
    proof: &<Groth16<Bls12_381> as SNARK<Fq>>::Proof,
    commit: &PedersenCommitment,
) -> bool {
    let pvk = prepare_verifying_key(&param.vk);
    let inputs = [commit.x, commit.y];
    verify_proof(&pvk, &proof, &inputs[..]).unwrap()
}
