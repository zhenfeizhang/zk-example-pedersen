use ark_marlin::*;
use crate::r1cs::*;
use crate::pedersen::*;
use ark_relations::r1cs::ConstraintSystem;
use ark_ff::UniformRand;
use ark_bls12_381::Bls12_381;
use ark_ed_on_bls12_381::*;
use ark_crypto_primitives::commitment::pedersen::Randomness;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_poly::univariate::DensePolynomial;
use blake2::Blake2s;

pub fn marlin_test(){
    let mut rng = rand::thread_rng();
    let len = 256;
    let param = pedersen_setup(&[0u8; 32]);
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
    circuit.clone().generate_constraints(sanity_cs.clone()).unwrap();
    let res = sanity_cs.is_satisfied().unwrap();


    let no_cs = sanity_cs.num_constraints();
    let no_var = sanity_cs.num_witness_variables();
    let no_non_zero = 0;//sanity_cs.num_instance_variables();

    type MultiPC = MarlinKZG10<Bls12_381, DensePolynomial<Fq>>;
    type MarlinInst = Marlin<Fq, MultiPC, Blake2s>;

    let srs = MarlinInst::universal_setup(no_cs, no_var, no_non_zero, &mut rng).unwrap();
    println!("srs generated");

    let (pk, vk) = MarlinInst::index(&srs, circuit.clone()).unwrap();
    println!("keys generated");


    let proof = MarlinInst::prove(&pk, circuit.clone(), &mut rng).unwrap();
    println!("proof generated");


    assert!(MarlinInst::verify(&vk, &[commit.x, commit.y], &proof, &mut rng).unwrap());

}