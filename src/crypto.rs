use crate::cipher::ring::RingCipher;
use crate::cipher::Cipher;
use crate::CipherMeta;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use secrets::SecretVec;

#[must_use]
pub fn create_rng() -> impl RngCore + CryptoRng {
    ChaCha20Rng::from_entropy()
}

pub fn create_cipher(cipher_meta: CipherMeta, key: &SecretVec<u8>) -> Box<dyn Cipher> {
    match cipher_meta {
        CipherMeta::Ring { alg } => Box::new(RingCipher::new(alg, key)),
    }
}
