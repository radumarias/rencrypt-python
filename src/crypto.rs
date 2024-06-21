use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

#[must_use]
/// Create a new cryptographically secure random number generator that implements also [CryptoRng].
pub fn create_rng() -> Box<dyn RngCore + Send + Sync> {
    Box::new(ChaCha20Rng::from_entropy())
}
