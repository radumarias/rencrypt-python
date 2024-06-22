use std::io;
use std::sync::{Arc, Mutex};

use ring::aead::{
    Aad, BoundKey, OpeningKey, SealingKey, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
};
use secrets::SecretVec;

use crate::cipher::{
    create_aad, Cipher, ExistingNonceSequence, HybridNonceSequence, HybridNonceSequenceWrapper,
};
use crate::RingAlgorithm;

pub struct RingCipher {
    sealing_key: Arc<Mutex<SealingKey<HybridNonceSequenceWrapper>>>,
    nonce_sequence: Arc<Mutex<HybridNonceSequence>>,
    last_nonce: Arc<Mutex<Vec<u8>>>,
    opening_key: Arc<Mutex<OpeningKey<ExistingNonceSequence>>>,
}

impl RingCipher {
    pub fn new(algorithm: RingAlgorithm, key: &SecretVec<u8>) -> io::Result<Self> {
        let (sealing_key, nonce_sequence) = create_sealing_key(algorithm, key)?;
        let (opening_key, last_nonce) = create_opening_key(algorithm, key)?;

        Ok(Self {
            sealing_key: Arc::new(Mutex::new(sealing_key)),
            nonce_sequence,
            last_nonce,
            opening_key: Arc::new(Mutex::new(opening_key)),
        })
    }
}

impl Cipher for RingCipher {
    fn seal_in_place<'a>(
        &self,
        plaintext: &'a mut [u8],
        block_index: Option<u64>,
        aad: Option<&[u8]>,
        nonce: Option<&[u8]>,
        tag_out: &mut [u8],
        nonce_out: Option<&mut [u8]>,
    ) -> io::Result<&'a mut [u8]> {
        // lock here to keep the lock while encrypting
        let mut sealing_key = self.sealing_key.lock().unwrap();

        let aad = create_aad(block_index, aad);
        let aad = Aad::<Vec<u8>>::from(aad);
        if let Some(nonce) = nonce {
            self.nonce_sequence.lock().unwrap().next_nonce = Some(nonce.to_vec());
        }

        let tag = sealing_key
            .seal_in_place_separate_tag(aad, plaintext)
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("encryption failed {err}"),
                )
            })?;

        tag_out.copy_from_slice(tag.as_ref());
        nonce_out.map(|n| {
            n.copy_from_slice(nonce.unwrap_or(&self.nonce_sequence.lock().unwrap().last_nonce));
            n
        });

        Ok(plaintext)
    }

    fn open_in_place<'a>(
        &self,
        ciphertext_and_tag: &'a mut [u8],
        block_index: Option<u64>,
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> io::Result<&'a mut [u8]> {
        // lock here to keep the lock while decrypting
        let mut opening_key = self.opening_key.lock().unwrap();

        self.last_nonce.lock().unwrap().copy_from_slice(nonce);
        let aad = create_aad(block_index, aad);
        let aad = Aad::<Vec<u8>>::from(aad);

        let plaintext = opening_key
            .open_within(aad, ciphertext_and_tag, 0..)
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("decryption failed {err}"),
                )
            })?;
        Ok(plaintext)
    }
}

type CreateSealingKeyResult = io::Result<(
    SealingKey<HybridNonceSequenceWrapper>,
    Arc<Mutex<HybridNonceSequence>>,
)>;

fn create_sealing_key(alg: RingAlgorithm, key: &SecretVec<u8>) -> CreateSealingKeyResult {
    // Create a new NonceSequence type which generates nonces
    let nonce_seq = Arc::new(Mutex::new(HybridNonceSequence::new(
        get_algorithm(alg).nonce_len(),
    )));
    let nonce_sequence = nonce_seq.clone();
    let nonce_wrapper = HybridNonceSequenceWrapper::new(nonce_seq.clone());
    // Create a new AEAD key without a designated role or nonce sequence
    let unbound_key = UnboundKey::new(get_algorithm(alg), &key.borrow())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid key"))?;

    // Create a new AEAD key for encrypting and signing ("sealing"), bound to a nonce sequence
    // The SealingKey can be used multiple times, each time a new nonce will be used
    let sealing_key = SealingKey::new(unbound_key, nonce_wrapper);
    Ok((sealing_key, nonce_sequence))
}

type CreateOpeningKeyResult = io::Result<(OpeningKey<ExistingNonceSequence>, Arc<Mutex<Vec<u8>>>)>;

fn create_opening_key(alg: RingAlgorithm, key: &SecretVec<u8>) -> CreateOpeningKeyResult {
    let last_nonce = Arc::new(Mutex::new(vec![0_u8; get_algorithm(alg).nonce_len()]));
    let unbound_key = UnboundKey::new(get_algorithm(alg), &key.borrow())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid key"))?;
    let nonce_sequence = ExistingNonceSequence::new(last_nonce.clone());
    let opening_key = OpeningKey::new(unbound_key, nonce_sequence);
    Ok((opening_key, last_nonce))
}

fn get_algorithm(alg: RingAlgorithm) -> &'static ring::aead::Algorithm {
    match alg {
        RingAlgorithm::ChaCha20Poly1305 => &CHACHA20_POLY1305,
        RingAlgorithm::Aes128Gcm => &AES_128_GCM,
        RingAlgorithm::Aes256Gcm => &AES_256_GCM,
    }
}

pub(super) fn key_len(algorithm: RingAlgorithm) -> usize {
    get_algorithm(algorithm).key_len()
}

pub(super) fn nonce_len(algorithm: RingAlgorithm) -> usize {
    get_algorithm(algorithm).nonce_len()
}

pub(super) fn tag_len(algorithm: RingAlgorithm) -> usize {
    get_algorithm(algorithm).tag_len()
}
