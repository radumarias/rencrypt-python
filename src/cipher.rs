use std::io;
use std::sync::{Arc, Mutex};

use crate::cipher::orion::OrionCipher;
use ::ring::aead::{Nonce, NonceSequence};
use ::ring::error::Unspecified;
use pyo3::prelude::PyByteArrayMethods;
use pyo3::types::PyByteArray;
use pyo3::{pyclass, pymethods, Bound};
use rand_core::RngCore;
use secrets::SecretVec;
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumIter};

use crate::cipher::ring::RingCipher;
use crate::cipher::sodiumoxide::SodiumoxideCipher;
use crate::crypto;

mod orion;
pub(crate) mod ring;
pub(crate) mod rust_crypto;
pub(crate) mod sodiumoxide;

#[pyclass]
#[derive(Debug, Clone, Copy, EnumIter, Display, Serialize, Deserialize)]
pub enum CipherMeta {
    Ring { alg: RingAlgorithm },
    RustCrypto { alg: RustCryptoAlgorithm },
    Sodiumoxide { alg: SodiumoxideAlgorithm },
    Orion { alg: OrionAlgorithm },
}

#[allow(dead_code)]
pub(crate) trait Cipher: Send + Sync {
    fn seal_in_place<'a>(
        &self,
        plaintext: &'a mut [u8],
        block_index: Option<u64>,
        aad: Option<&[u8]>,
        nonce: Option<&[u8]>,
        tag_out: &mut [u8],
        nonce_out: Option<&mut [u8]>,
    ) -> io::Result<&'a mut [u8]>;

    fn open_in_place<'a>(
        &self,
        ciphertext_and_tag: &'a mut [u8],
        block_index: Option<u64>,
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> io::Result<&'a mut [u8]>;
}

#[pyclass]
#[derive(Debug, Clone, Copy, EnumIter, Display, Serialize, Deserialize, Default)]
pub enum RingAlgorithm {
    ChaCha20Poly1305,
    Aes128Gcm,
    #[default]
    Aes256Gcm,
}

#[pyclass]
#[derive(Debug, Clone, Copy, EnumIter, Display, Serialize, Deserialize, Default)]
pub enum RustCryptoAlgorithm {
    ChaCha20Poly1305,
    XChaCha20Poly1305,
    Aes128Gcm,
    #[default]
    Aes256Gcm,
    Aes128GcmSiv,
    Aes256GcmSiv,
    Aes128Siv,
    Aes256Siv,
    Ascon128,
    Ascon128a,
    Ascon80pq,
    DeoxysI128,
    DeoxysI256,
    DeoxysII128,
    DeoxysII256,
    Aes128Eax,
    Aes256Eax,
}

#[pyclass]
#[derive(Debug, Clone, Copy, EnumIter, Display, Serialize, Deserialize, Default)]
pub enum SodiumoxideAlgorithm {
    ChaCha20Poly1305,
    #[default]
    ChaCha20Poly1305Ieft,
    XChaCha20Poly1305Ieft,
    // #[default]
    // Aes256Gcm,
}

#[pyclass]
#[derive(Debug, Clone, Copy, EnumIter, Display, Serialize, Deserialize, Default)]
pub enum OrionAlgorithm {
    #[default]
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

#[pyclass]
#[derive(Debug, Clone, Copy, EnumIter, Display, Serialize, Deserialize, Default)]
pub enum HPKEAlgorithm {
    Aes128Gcm,
    #[default]
    Aes256Gcm,
    ChaCha20Poly1305,
}

#[pymethods]
impl CipherMeta {
    /// In bytes.
    pub fn key_len(&self) -> usize {
        key_len(*self)
    }

    /// In bytes.
    pub fn tag_len(&self) -> usize {
        tag_len(*self)
    }

    /// In bytes.
    pub fn nonce_len(&self) -> usize {
        nonce_len(*self)
    }

    pub fn overhead(&self) -> usize {
        overhead(*self)
    }

    pub fn ciphertext_len(&self, plaintext_len: usize) -> usize {
        plaintext_len + overhead(*self)
    }

    // /// Max length (in bytes) of the plaintext that can be encrypted before becoming unsafe.
    // #[must_use]
    // #[allow(clippy::use_self)]
    // pub const fn max_plaintext_len(&self) -> usize {
    //     match self {
    //         Ring {
    //             alg: RingAlgorithm::ChaCha20Poly1305,
    //         } => (2_usize.pow(32) - 1) * 64,
    //         Ring {
    //             alg: RingAlgorithm::Aes256Gcm,
    //         } => (2_usize.pow(39) - 256) / 8,
    //         RustCrypto {
    //             alg: RustCryptoAlgorithm::ChaCha20Poly1305,
    //         } => (2_usize.pow(32) - 1) * 64,
    //         RustCrypto {
    //             alg: RustCryptoAlgorithm::Aes256Gcm,
    //         } => (2_usize.pow(39) - 256) / 8,
    //         RustCrypto {
    //             alg: RustCryptoAlgorithm::Aes128Gcm,
    //         } => {}
    //     }
    // }

    pub fn generate_key(&self, key: &Bound<'_, PyByteArray>) {
        let mut rng = crypto::create_rng();
        unsafe {
            rng.fill_bytes(key.as_bytes_mut());
        }
    }
}

fn key_len(cipher_meta: CipherMeta) -> usize {
    match cipher_meta {
        CipherMeta::Ring { alg } => ring::key_len(alg),
        CipherMeta::RustCrypto { alg } => rust_crypto::key_len(alg),
        CipherMeta::Sodiumoxide { alg } => sodiumoxide::key_len(alg),
        CipherMeta::Orion { alg } => orion::key_len(alg),
    }
}

fn nonce_len(cipher_meta: CipherMeta) -> usize {
    match cipher_meta {
        CipherMeta::Ring { alg } => ring::nonce_len(alg),
        CipherMeta::RustCrypto { alg } => rust_crypto::nonce_len(alg),
        CipherMeta::Sodiumoxide { alg } => sodiumoxide::nonce_len(alg),
        CipherMeta::Orion { alg } => orion::nonce_len(alg),
    }
}

fn tag_len(cipher_meta: CipherMeta) -> usize {
    match cipher_meta {
        CipherMeta::Ring { alg } => ring::tag_len(alg),
        CipherMeta::RustCrypto { alg } => rust_crypto::tag_len(alg),
        CipherMeta::Sodiumoxide { alg } => sodiumoxide::tag_len(alg),
        CipherMeta::Orion { alg } => orion::tag_len(alg),
    }
}

fn overhead(cipher_meta: CipherMeta) -> usize {
    tag_len(cipher_meta) + nonce_len(cipher_meta)
}

pub fn new_cipher(cipher_meta: CipherMeta, key: &SecretVec<u8>) -> io::Result<Box<dyn Cipher>> {
    match cipher_meta {
        CipherMeta::Ring { alg } => Ok(Box::new(RingCipher::new(alg, key)?)),
        CipherMeta::RustCrypto { alg } => rust_crypto::new(alg, key),
        CipherMeta::Sodiumoxide { alg } => Ok(Box::new(SodiumoxideCipher::new(alg, key)?)),
        CipherMeta::Orion { alg } => Ok(Box::new(OrionCipher::new(alg, key)?)),
    }
}

#[allow(dead_code)]
pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub(crate) struct ExistingNonceSequence {
    last_nonce: Arc<Mutex<Vec<u8>>>,
}

impl ExistingNonceSequence {
    pub fn new(last_nonce: Arc<Mutex<Vec<u8>>>) -> Self {
        Self { last_nonce }
    }
}

impl NonceSequence for ExistingNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        Nonce::try_assume_unique_for_key(&self.last_nonce.lock().unwrap())
    }
}

pub struct RandomNonceSequence {
    rng: Box<dyn RngCore + Send + Sync>,
    last_nonce: Vec<u8>,
}

impl RandomNonceSequence {
    #[allow(dead_code)]
    pub fn new(nonce_len: usize) -> Self {
        Self {
            rng: Box::new(crypto::create_rng()),
            last_nonce: vec![0; nonce_len],
        }
    }
}

impl NonceSequence for RandomNonceSequence {
    // called once for each seal operation
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.rng.fill_bytes(&mut self.last_nonce);
        Nonce::try_assume_unique_for_key(&self.last_nonce)
    }
}

pub struct RandomNonceSequenceWrapper {
    inner: Arc<Mutex<RandomNonceSequence>>,
}

impl RandomNonceSequenceWrapper {
    #[allow(dead_code)]
    pub fn new(inner: Arc<Mutex<RandomNonceSequence>>) -> Self {
        Self { inner }
    }
}

impl NonceSequence for RandomNonceSequenceWrapper {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.inner.lock().unwrap().advance()
    }
}

pub struct HybridNonceSequence {
    rng: Box<dyn RngCore + Send + Sync>,
    last_nonce: Vec<u8>,
    next_nonce: Option<Vec<u8>>,
}

impl HybridNonceSequence {
    pub fn new(nonce_len: usize) -> Self {
        Self {
            rng: Box::new(crypto::create_rng()),
            last_nonce: vec![0; nonce_len],
            next_nonce: None,
        }
    }
}

impl NonceSequence for HybridNonceSequence {
    // called once for each seal operation
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        if let Some(next_nonce) = self.next_nonce.take() {
            return Nonce::try_assume_unique_for_key(&next_nonce);
        }
        self.rng.fill_bytes(&mut self.last_nonce);
        Nonce::try_assume_unique_for_key(&self.last_nonce)
    }
}

pub struct HybridNonceSequenceWrapper {
    inner: Arc<Mutex<HybridNonceSequence>>,
}

impl HybridNonceSequenceWrapper {
    pub fn new(inner: Arc<Mutex<HybridNonceSequence>>) -> Self {
        Self { inner }
    }
}

impl NonceSequence for HybridNonceSequenceWrapper {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.inner.lock().unwrap().advance()
    }
}

pub(crate) fn create_aad(block_index: Option<u64>, aad: Option<&[u8]>) -> Vec<u8> {
    let len = {
        let mut len = 0;
        if let Some(aad) = aad {
            len += aad.len();
        }
        if block_index.is_some() {
            len += 8;
        }
        len
    };
    let mut aad2 = vec![0_u8; len];
    let mut offset = 0;
    aad.map(|aad| {
        aad2[..aad.len()].copy_from_slice(aad);
        offset += aad.len();
        aad
    });
    block_index.map(|block_index| {
        let block_index_bytes = block_index.to_le_bytes();
        aad2[offset..].copy_from_slice(&block_index_bytes);
        block_index
    });
    aad2
}
