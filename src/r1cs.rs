use crate::pedersen::*;
use ark_crypto_primitives::{commitment::pedersen::constraints::CommGadget, CommitmentGadget};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, *};
use ark_r1cs_std::{
	alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, groups::curves::twisted_edwards::AffineVar,
	uint8::UInt8,
};
use ark_relations::r1cs::{
	ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_std::{println, vec, vec::Vec};

// alias for R1CS gadgets of pedersen commitment scheme
pub(crate) type PedersenComSchemeVar = CommGadget<JubJub, EdwardsVar, Window>;
pub(crate) type PedersenParamVar =
	<PedersenComSchemeVar as CommitmentGadget<PedersenComScheme, Fq>>::ParametersVar;
pub(crate) type PedersenRandomnessVar =
	<PedersenComSchemeVar as CommitmentGadget<PedersenComScheme, Fq>>::RandomnessVar;
pub(crate) type PedersenCommitmentVar = AffineVar<EdwardsParameters, FpVar<Fq>>;

// ZK proved statements:
//  commit(data, open) = commitment
// where both data and open are kept secret
// while the commitment is shared between the prover and verifier
#[derive(Clone)]
pub struct PedersenComCircuit {
	pub param: PedersenParam,
	pub input: Vec<u8>,
	pub open: PedersenRandomness,
	pub commit: PedersenCommitment,
}

// =============================
// constraints
// =============================
impl ConstraintSynthesizer<Fq> for PedersenComCircuit {
	fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
		#[cfg(debug_assertions)]
		println!("is setup mode?: {}", cs.is_in_setup_mode());
		let _cs_no = cs.num_constraints();
		// step 1. Allocate Parameters for perdersen commitment
		let param_var =
			PedersenParamVar::new_input(ark_relations::ns!(cs, "gadget_parameters"), || {
				Ok(&self.param)
			})
			.unwrap();
		let _cs_no = cs.num_constraints() - _cs_no;
		#[cfg(debug_assertions)]
		println!("cs for parameters: {}", _cs_no);
		let _cs_no = cs.num_constraints();
		// step 2. Allocate inputs
		let mut input_var = vec![];
		for input_byte in self.input.iter() {
			input_var.push(UInt8::new_witness(cs.clone(), || Ok(*input_byte)).unwrap());
		}

		let _cs_no = cs.num_constraints() - _cs_no;
		#[cfg(debug_assertions)]
		println!("cs for account: {}", _cs_no);
		let _cs_no = cs.num_constraints();

		// step 3. Allocate the opening
		let open_var =
			PedersenRandomnessVar::new_witness(ark_relations::ns!(cs, "gadget_randomness"), || {
				Ok(&self.open)
			})
			.unwrap();

		let _cs_no = cs.num_constraints() - _cs_no;
		#[cfg(debug_assertions)]
		println!("cs for opening: {}", _cs_no);
		let _cs_no = cs.num_constraints();

		// step 4. Allocate the output
		let result_var = PedersenComSchemeVar::commit(&param_var, &input_var, &open_var).unwrap();

		let _cs_no = cs.num_constraints() - _cs_no;
		#[cfg(debug_assertions)]
		println!("cs for commitment: {}", _cs_no);
		let _cs_no = cs.num_constraints();

		// circuit to compare the commited value with supplied value

		let commitment_var2 =
			PedersenCommitmentVar::new_input(ark_relations::ns!(cs, "gadget_commitment"), || {
				Ok(self.commit)
			})
			.unwrap();
		result_var.enforce_equal(&commitment_var2).unwrap();

		let _cs_no = cs.num_constraints() - _cs_no;
		#[cfg(debug_assertions)]
		println!("cs for comparison: {}", _cs_no);

		#[cfg(debug_assertions)]
		println!("total cs for Commitment: {}", cs.num_constraints());
		Ok(())
	}
}

pub fn sanity_check(circuit: PedersenComCircuit) -> bool {
	let _len = circuit.input.len();
	let sanity_cs = ConstraintSystem::<Fq>::new_ref();
	circuit.generate_constraints(sanity_cs.clone()).unwrap();
	let res = sanity_cs.is_satisfied().unwrap();

	#[cfg(debug_assertions)]
	{
		println!("are the constraints satisfied?: {}\n", res);
		println!(
			"number of constraint {} for data size: {}\n",
			sanity_cs.num_constraints(),
			_len
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
