use crate::cipher::{
    Cipher, ExistingNonceSequence, HybridNonceSequence, HybridNonceSequenceWrapper,
};
use crate::RingAlgorithm;
use ring::aead::{
    Aad, BoundKey, OpeningKey, SealingKey, UnboundKey, AES_256_GCM, CHACHA20_POLY1305,
};
use secrets::SecretVec;
use std::io;
use std::sync::{Arc, Mutex};

pub struct RingCipher {
    sealing_key: Arc<Mutex<SealingKey<HybridNonceSequenceWrapper>>>,
    nonce_sequence: Arc<Mutex<HybridNonceSequence>>,
    last_nonce: Arc<Mutex<Vec<u8>>>,
    opening_key: Arc<Mutex<OpeningKey<ExistingNonceSequence>>>,
}

impl RingCipher {
    pub fn new(algorithm: RingAlgorithm, key: &SecretVec<u8>) -> Self {
        let (sealing_key, nonce_sequence) = create_ring_sealing_key(algorithm, key);
        let (opening_key, last_nonce) = create_ring_opening_key(algorithm, key);

        Self {
            sealing_key: Arc::new(Mutex::new(sealing_key)),
            nonce_sequence,
            last_nonce,
            opening_key: Arc::new(Mutex::new(opening_key)),
        }
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
    ) -> io::Result<&'a [u8]> {
        // lock here to keep the lock while encrypting
        let mut sealing_key = self.sealing_key.lock().unwrap();

        let aad = create_aad(block_index, aad);
        if let Some(nonce) = nonce {
            self.nonce_sequence.lock().unwrap().next_nonce = Some(nonce.to_vec());
        }

        let tag = sealing_key
            .seal_in_place_separate_tag(aad, plaintext)
            .unwrap();

        tag_out.copy_from_slice(tag.as_ref());
        if let Some(nonce_out) = nonce_out {
            if let Some(nonce) = nonce {
                nonce_out.copy_from_slice(nonce);
            } else {
                nonce_out.copy_from_slice(&self.nonce_sequence.lock().unwrap().last_nonce);
            }
        }

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

        let plaintext = opening_key
            .open_within(aad, ciphertext_and_tag, 0..)
            .unwrap();
        Ok(plaintext)
    }
}

fn create_ring_sealing_key(
    alg: RingAlgorithm,
    key: &SecretVec<u8>,
) -> (
    SealingKey<HybridNonceSequenceWrapper>,
    Arc<Mutex<HybridNonceSequence>>,
) {
    // Create a new NonceSequence type which generates nonces
    let nonce_seq = Arc::new(Mutex::new(HybridNonceSequence::new(
        get_algorithm(alg).nonce_len(),
    )));
    let nonce_sequence = nonce_seq.clone();
    let nonce_wrapper = HybridNonceSequenceWrapper::new(nonce_seq.clone());
    // Create a new AEAD key without a designated role or nonce sequence
    let unbound_key = UnboundKey::new(get_algorithm(alg), &key.borrow()).unwrap();

    // Create a new AEAD key for encrypting and signing ("sealing"), bound to a nonce sequence
    // The SealingKey can be used multiple times, each time a new nonce will be used
    let sealing_key = SealingKey::new(unbound_key, nonce_wrapper);
    (sealing_key, nonce_sequence)
}

fn create_ring_opening_key(
    alg: RingAlgorithm,
    key: &SecretVec<u8>,
) -> (OpeningKey<ExistingNonceSequence>, Arc<Mutex<Vec<u8>>>) {
    let last_nonce = Arc::new(Mutex::new(vec![0_u8; get_algorithm(alg).nonce_len()]));
    let unbound_key = UnboundKey::new(get_algorithm(alg), &key.borrow()).unwrap();
    let nonce_sequence = ExistingNonceSequence::new(last_nonce.clone());
    let opening_key = OpeningKey::new(unbound_key, nonce_sequence);
    (opening_key, last_nonce)
}

fn create_aad(block_index: Option<u64>, aad: Option<&[u8]>) -> Aad<Vec<u8>> {
    let aad = {
        let len = {
            let mut len = 0;
            if let Some(aad) = aad {
                len += aad.len();
            }
            if let Some(_) = block_index {
                len += 8;
            }
            len
        };
        let mut aad2 = vec![0_u8; len];
        let mut offset = 0;
        if let Some(aad) = aad {
            aad2[..aad.len()].copy_from_slice(aad);
            offset += aad.len();
        }
        if let Some(block_index) = block_index {
            let block_index_bytes = block_index.to_le_bytes();
            aad2[offset..].copy_from_slice(&block_index_bytes);
        }
        Aad::<Vec<u8>>::from(aad2)
    };
    aad
}

pub fn get_algorithm(alg: RingAlgorithm) -> &'static ring::aead::Algorithm {
    match alg {
        RingAlgorithm::ChaCha20Poly1305 => &CHACHA20_POLY1305,
        RingAlgorithm::AES256GCM => &AES_256_GCM,
    }
}
