use ark_crypto_primitives::{
	commitment::{
		pedersen,
		pedersen::{Commitment, Randomness},
	},
	CommitmentScheme,
};
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

//=======================
// curves: JubJub and BLS
//=======================
pub type JubJub = ark_ed_on_bls12_381::EdwardsProjective;

//=======================
// pedersen hash and related defintions
// the hash function is defined over the JubJub curve
// this parameter allows us to commit to 256 * 8 = 2048 bits
//=======================
pub const PERDERSON_WINDOW_SIZE: usize = 8;
pub const PERDERSON_WINDOW_NUM: usize = 256;

#[derive(Clone)]
pub struct Window;
impl pedersen::Window for Window {
	const WINDOW_SIZE: usize = PERDERSON_WINDOW_SIZE;
	const NUM_WINDOWS: usize = PERDERSON_WINDOW_NUM;
}

// alias for pedersen commitment scheme
pub type PedersenComScheme = Commitment<JubJub, Window>;
pub type PedersenCommitment = <PedersenComScheme as CommitmentScheme>::Output;
pub type PedersenParam = <PedersenComScheme as CommitmentScheme>::Parameters;
pub type PedersenRandomness = Randomness<JubJub>;

pub fn pedersen_setup(seed: &[u8; 32]) -> PedersenParam {
	let mut rng = ChaCha20Rng::from_seed(*seed);
	PedersenComScheme::setup(&mut rng).unwrap()
}

pub fn pedersen_commit(
	x: &[u8],
	param: &PedersenParam,
	r: &PedersenRandomness,
) -> PedersenCommitment {
	PedersenComScheme::commit(param, &x, r).unwrap()
}
