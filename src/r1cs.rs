use crate::pedersen::*;
use algebra::ed_on_bls12_381::*;
use crypto_primitives::commitment::pedersen::constraints::CommGadget;
use crypto_primitives::CommitmentGadget;
use r1cs_core::ConstraintSynthesizer;
use r1cs_core::ConstraintSystemRef;
use r1cs_core::SynthesisError;
use r1cs_std::alloc::AllocVar;
use r1cs_std::ed_on_bls12_381::EdwardsVar;
use r1cs_std::eq::EqGadget;
use r1cs_std::fields::fp::FpVar;
use r1cs_std::groups::curves::twisted_edwards::AffineVar;
use r1cs_std::uint8::UInt8;

// alias for R1CS gadgets of pedersen commitment scheme
pub type PedersenComSchemeVar = CommGadget<JubJub, EdwardsVar, Window>;
pub type PedersenParamVar =
    <PedersenComSchemeVar as CommitmentGadget<PedersenComScheme, Fq>>::ParametersVar;
pub type PedersenRandomnessVar =
    <PedersenComSchemeVar as CommitmentGadget<PedersenComScheme, Fq>>::RandomnessVar;
pub type PedersenCommitmentVar = AffineVar<EdwardsParameters, FpVar<Fq>>;

// ZK proved statements:
//  commit(data, open) = commitment
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
            PedersenParamVar::new_witness(r1cs_core::ns!(cs, "gadget_parameters"), || {
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
            PedersenRandomnessVar::new_witness(r1cs_core::ns!(cs, "gadget_randomness"), || {
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
            PedersenCommitmentVar::new_input(r1cs_core::ns!(cs, "gadget_commitment"), || {
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
