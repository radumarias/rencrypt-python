use std::io;
use std::sync::{Arc, Mutex};

use ::ring::aead::{Nonce, NonceSequence};
use ::ring::error::Unspecified;
use pyo3::prelude::PyByteArrayMethods;
use pyo3::types::PyByteArray;
use pyo3::{pyclass, pymethods, Bound};
use rand_core::RngCore;

use crate::cipher::CipherMeta::Ring;
use crate::crypto;

pub(crate) mod ring;

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
    ) -> io::Result<&'a [u8]>;

    fn open_in_place<'a>(
        &self,
        ciphertext_and_tag: &'a mut [u8],
        block_index: Option<u64>,
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> io::Result<&'a mut [u8]>;
}

#[pyclass]
#[derive(Debug, Clone, Copy)]
pub enum RingAlgorithm {
    ChaCha20Poly1305,
    AES256GCM,
}

#[pyclass]
#[derive(Debug, Clone, Copy)]
pub enum RustCryptoAlgorithm {
    ChaCha20Poly1305,
    AES256GCM,
}

#[pyclass]
#[derive(Debug, Clone, Copy)]
pub enum CipherMeta {
    Ring { alg: RingAlgorithm },
    // RustCrypto { alg: RustCryptoAlgorithm },
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

    /// Max length (in bytes) of the plaintext that can be encrypted before becoming unsafe.
    #[must_use]
    #[allow(clippy::use_self)]
    pub const fn max_plaintext_len(&self) -> usize {
        match self {
            Ring {
                alg: RingAlgorithm::ChaCha20Poly1305,
            } => (2_usize.pow(32) - 1) * 64,
            Ring {
                alg: RingAlgorithm::AES256GCM,
            } => (2_usize.pow(39) - 256) / 8,
            // RustCrypto { alg: RustCryptoAlgorithm::ChaCha20Poly1305 } => (2_usize.pow(32) - 1) * 64,
            // RustCrypto { alg: RustCryptoAlgorithm::AES256GCM } => (2_usize.pow(39) - 256) / 8,
        }
    }

    pub fn generate_key(&self, key: &Bound<'_, PyByteArray>) {
        let mut rng = crypto::create_rng();
        unsafe {
            rng.fill_bytes(key.as_bytes_mut());
        }
    }
}

fn nonce_len(cipher_meta: CipherMeta) -> usize {
    match cipher_meta {
        Ring { alg } => ring::get_algorithm(alg).nonce_len(),
        // RustCrypto { alg } => (alg).nonce_len(),
    }
}

fn tag_len(cipher_meta: CipherMeta) -> usize {
    match cipher_meta {
        Ring { alg } => ring::get_algorithm(alg).tag_len(),
        // RustCrypto { alg } => (alg).tag_len(),
    }
}

fn key_len(cipher_meta: CipherMeta) -> usize {
    match cipher_meta {
        Ring { alg } => ring::get_algorithm(alg).key_len(),
        // RustCrypto { alg } => (alg).key_len(),
    }
}

fn overhead(cipher_meta: CipherMeta) -> usize {
    tag_len(cipher_meta) + nonce_len(cipher_meta)
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
