use crate::cipher::Cipher;
use crate::{cipher, crypto, RustCryptoAlgorithm};
use aead::{AeadInPlace, KeySizeUser, Nonce, Tag};
use aes::Aes128;
use aes::Aes256;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit};
use aes_gcm_siv::{Aes128GcmSiv, Aes256GcmSiv};
use aes_siv::{Aes128SivAead, Aes256SivAead};
use ascon_aead::{Ascon128, Ascon128a, Ascon80pq};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use deoxys::{DeoxysI128, DeoxysI256, DeoxysII128, DeoxysII256};
use eax::Eax;
use rand_core::RngCore;
use secrets::SecretVec;
use std::cell::RefCell;
use std::io;
use std::sync::{Mutex, RwLock};

pub type Aes128Eax = Eax<Aes128>;
pub type Aes256Eax = Eax<Aes256>;

thread_local! {
    static NONCE: RefCell<Vec<u8>> = RefCell::new(vec![0; 24]);
}

pub struct RustCryptoCipher<T: AeadInPlace + Send + Sync> {
    cipher: RwLock<T>,
    rng: Mutex<Box<dyn RngCore + Send + Sync>>,
    nonce_len: usize,
}

impl<T: AeadInPlace + Send + Sync> RustCryptoCipher<T> {
    fn new_inner(inner: T, nonce_len: usize) -> Self {
        Self {
            cipher: RwLock::new(inner),
            rng: Mutex::new(Box::new(crypto::create_rng())),
            nonce_len,
        }
    }
}

impl<T: AeadInPlace + Send + Sync> Cipher for RustCryptoCipher<T> {
    fn seal_in_place<'a>(
        &self,
        plaintext: &'a mut [u8],
        block_index: Option<u64>,
        aad: Option<&[u8]>,
        nonce: Option<&[u8]>,
        tag_out: &mut [u8],
        nonce_out: Option<&mut [u8]>,
    ) -> io::Result<&'a mut [u8]> {
        if let Some(nonce) = nonce {
            seal_in_place(
                &self.cipher,
                plaintext,
                block_index,
                aad,
                nonce,
                tag_out,
                nonce_out,
            )
        } else {
            NONCE.with(|nonce| {
                let mut nonce = nonce.borrow_mut();
                self.rng
                    .lock()
                    .unwrap()
                    .fill_bytes(&mut nonce[..self.nonce_len]);
                seal_in_place(
                    &self.cipher,
                    plaintext,
                    block_index,
                    aad,
                    &nonce[..self.nonce_len],
                    tag_out,
                    nonce_out,
                )
            })
        }
    }

    fn open_in_place<'a>(
        &self,
        ciphertext_and_tag: &'a mut [u8],
        block_index: Option<u64>,
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> io::Result<&'a mut [u8]> {
        let aad = cipher::create_aad(block_index, aad);
        let nonce = Nonce::<T>::from_slice(nonce);
        let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(ciphertext_and_tag.len() - 16);
        let tag = Tag::<T>::from_slice(tag);

        self.cipher
            .read()
            .unwrap()
            .decrypt_in_place_detached(nonce, &aad, ciphertext, tag)
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("decryption failed: {err}"),
                )
            })?;
        Ok(ciphertext)
    }
}

pub fn new(algorithm: RustCryptoAlgorithm, key: &SecretVec<u8>) -> io::Result<Box<dyn Cipher>> {
    match algorithm {
        RustCryptoAlgorithm::ChaCha20Poly1305 => Ok(Box::new(RustCryptoCipher::new_inner(
            ChaCha20Poly1305::new_from_slice(&key.borrow())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key length"))?,
            nonce_len(algorithm),
        ))),
        RustCryptoAlgorithm::XChaCha20Poly1305 => Ok(Box::new(RustCryptoCipher::new_inner(
            XChaCha20Poly1305::new_from_slice(&key.borrow())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key length"))?,
            nonce_len(algorithm),
        ))),
        RustCryptoAlgorithm::Aes128Gcm => Ok(Box::new(RustCryptoCipher::new_inner(
            Aes128Gcm::new_from_slice(&key.borrow())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key length"))?,
            nonce_len(algorithm),
        ))),
        RustCryptoAlgorithm::Aes256Gcm => Ok(Box::new(RustCryptoCipher::new_inner(
            Aes256Gcm::new_from_slice(&key.borrow())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key length"))?,
            nonce_len(algorithm),
        ))),
        RustCryptoAlgorithm::Aes128GcmSiv => Ok(Box::new(RustCryptoCipher::new_inner(
            Aes128GcmSiv::new_from_slice(&key.borrow())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key length"))?,
            nonce_len(algorithm),
        ))),
        RustCryptoAlgorithm::Aes256GcmSiv => Ok(Box::new(RustCryptoCipher::new_inner(
            Aes256GcmSiv::new_from_slice(&key.borrow())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key length"))?,
            nonce_len(algorithm),
        ))),
        RustCryptoAlgorithm::Aes128Siv => Ok(Box::new(RustCryptoCipher::new_inner(
            Aes128SivAead::new_from_slice(&key.borrow())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key length"))?,
            nonce_len(algorithm),
        ))),
        RustCryptoAlgorithm::Aes256Siv => Ok(Box::new(RustCryptoCipher::new_inner(
            Aes256SivAead::new_from_slice(&key.borrow())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key length"))?,
            nonce_len(algorithm),
        ))),
        RustCryptoAlgorithm::Ascon128 => Ok(Box::new(RustCryptoCipher::new_inner(
            Ascon128::new_from_slice(&key.borrow())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key length"))?,
            nonce_len(algorithm),
        ))),
        RustCryptoAlgorithm::Ascon128a => Ok(Box::new(RustCryptoCipher::new_inner(
            Ascon128a::new_from_slice(&key.borrow())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key length"))?,
            nonce_len(algorithm),
        ))),
        RustCryptoAlgorithm::Ascon80pq => Ok(Box::new(RustCryptoCipher::new_inner(
            Ascon80pq::new_from_slice(&key.borrow())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key length"))?,
            nonce_len(algorithm),
        ))),
        RustCryptoAlgorithm::DeoxysI128 => Ok(Box::new(RustCryptoCipher::new_inner(
            DeoxysI128::new_from_slice(&key.borrow())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key length"))?,
            nonce_len(algorithm),
        ))),
        RustCryptoAlgorithm::DeoxysI256 => Ok(Box::new(RustCryptoCipher::new_inner(
            DeoxysI256::new_from_slice(&key.borrow())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key length"))?,
            nonce_len(algorithm),
        ))),
        RustCryptoAlgorithm::DeoxysII128 => Ok(Box::new(RustCryptoCipher::new_inner(
            DeoxysII128::new_from_slice(&key.borrow())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key length"))?,
            nonce_len(algorithm),
        ))),
        RustCryptoAlgorithm::DeoxysII256 => Ok(Box::new(RustCryptoCipher::new_inner(
            DeoxysII256::new_from_slice(&key.borrow())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key length"))?,
            nonce_len(algorithm),
        ))),
        RustCryptoAlgorithm::Aes128Eax => Ok(Box::new(RustCryptoCipher::new_inner(
            Aes128Eax::new_from_slice(&key.borrow())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key length"))?,
            nonce_len(algorithm),
        ))),
        RustCryptoAlgorithm::Aes256Eax => Ok(Box::new(RustCryptoCipher::new_inner(
            Aes256Eax::new_from_slice(&key.borrow())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key length"))?,
            nonce_len(algorithm),
        ))),
    }
}

pub(super) fn key_len(algorithm: RustCryptoAlgorithm) -> usize {
    match algorithm {
        RustCryptoAlgorithm::ChaCha20Poly1305 => ChaCha20Poly1305::key_size(),
        RustCryptoAlgorithm::XChaCha20Poly1305 => XChaCha20Poly1305::key_size(),
        RustCryptoAlgorithm::Aes128Gcm => Aes128Gcm::key_size(),
        RustCryptoAlgorithm::Aes256Gcm => Aes256Gcm::key_size(),
        RustCryptoAlgorithm::Aes128GcmSiv => Aes128GcmSiv::key_size(),
        RustCryptoAlgorithm::Aes256GcmSiv => Aes256GcmSiv::key_size(),
        RustCryptoAlgorithm::Aes128Siv => Aes128SivAead::key_size(),
        RustCryptoAlgorithm::Aes256Siv => Aes256SivAead::key_size(),
        RustCryptoAlgorithm::Ascon128 => Ascon128::key_size(),
        RustCryptoAlgorithm::Ascon128a => Ascon128a::key_size(),
        RustCryptoAlgorithm::Ascon80pq => Ascon80pq::key_size(),
        RustCryptoAlgorithm::DeoxysI128 => DeoxysI128::key_size(),
        RustCryptoAlgorithm::DeoxysI256 => DeoxysI256::key_size(),
        RustCryptoAlgorithm::DeoxysII128 => DeoxysII128::key_size(),
        RustCryptoAlgorithm::DeoxysII256 => DeoxysII256::key_size(),
        RustCryptoAlgorithm::Aes128Eax => Aes128Eax::key_size(),
        RustCryptoAlgorithm::Aes256Eax => Aes256Eax::key_size(),
    }
}

pub(super) fn nonce_len(algorithm: RustCryptoAlgorithm) -> usize {
    match algorithm {
        RustCryptoAlgorithm::ChaCha20Poly1305
        | RustCryptoAlgorithm::Aes128Gcm
        | RustCryptoAlgorithm::Aes256Gcm
        | RustCryptoAlgorithm::Aes128GcmSiv
        | RustCryptoAlgorithm::Aes256GcmSiv => 12,

        RustCryptoAlgorithm::XChaCha20Poly1305 => 24,

        RustCryptoAlgorithm::Aes128Siv
        | RustCryptoAlgorithm::Aes256Siv
        | RustCryptoAlgorithm::Ascon128
        | RustCryptoAlgorithm::Ascon128a
        | RustCryptoAlgorithm::Ascon80pq
        | RustCryptoAlgorithm::Aes128Eax
        | RustCryptoAlgorithm::Aes256Eax => 16,

        RustCryptoAlgorithm::DeoxysI128 | RustCryptoAlgorithm::DeoxysI256 => 8,

        RustCryptoAlgorithm::DeoxysII128 | RustCryptoAlgorithm::DeoxysII256 => 15,
    }
}

pub(super) fn tag_len(_: RustCryptoAlgorithm) -> usize {
    16
}

fn seal_in_place<'a, T: AeadInPlace + Send + Sync>(
    cipher: &RwLock<T>,
    plaintext: &'a mut [u8],
    block_index: Option<u64>,
    aad: Option<&[u8]>,
    nonce: &[u8],
    tag_out: &mut [u8],
    nonce_out: Option<&mut [u8]>,
) -> io::Result<&'a mut [u8]> {
    let aad = cipher::create_aad(block_index, aad);
    let nonce2 = Nonce::<T>::from_slice(nonce);

    let tag = cipher
        .read()
        .unwrap()
        .encrypt_in_place_detached(nonce2, &aad, plaintext)
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("encryption failed: {err}"),
            )
        })?;

    tag_out.copy_from_slice(tag.as_ref());
    nonce_out.map(|nout| {
        nout.copy_from_slice(nonce);
        nout
    });

    Ok(plaintext)
}
