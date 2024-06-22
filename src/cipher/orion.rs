use crate::cipher::{self, Cipher, OrionAlgorithm};
use crate::crypto;
use orion::hazardous::aead;
use rand_core::RngCore;
use secrets::SecretVec;
use std::cell::RefCell;
use std::io;
use std::sync::Mutex;

thread_local! {
    static NONCE: RefCell<Vec<u8>> = RefCell::new(vec![0; 24]);
}

#[derive(Debug)]
enum CipherInner {
    ChaCha20Poly1305(aead::chacha20poly1305::SecretKey),
    XChaCha20Poly1305(aead::xchacha20poly1305::SecretKey),
}

pub struct OrionCipher {
    cipher: CipherInner,
    rng: Mutex<Box<dyn RngCore + Send + Sync>>,
    algorithm: OrionAlgorithm,
}

impl OrionCipher {
    pub fn new(algorithm: OrionAlgorithm, key: &SecretVec<u8>) -> io::Result<Self> {
        let rng = Mutex::new(crypto::create_rng());
        let cipher = match algorithm {
            OrionAlgorithm::ChaCha20Poly1305 => CipherInner::ChaCha20Poly1305(
                aead::chacha20poly1305::SecretKey::from_slice(&key.borrow())
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid key length"))?,
            ),
            OrionAlgorithm::XChaCha20Poly1305 => CipherInner::XChaCha20Poly1305(
                aead::xchacha20poly1305::SecretKey::from_slice(&key.borrow())
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid key length"))?,
            ),
        };

        Ok(Self {
            cipher,
            rng,
            algorithm,
        })
    }
}

impl Cipher for OrionCipher {
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
                self.algorithm,
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
                    .fill_bytes(&mut nonce[..nonce_len(self.algorithm)]);
                seal_in_place(
                    &self.cipher,
                    self.algorithm,
                    plaintext,
                    block_index,
                    aad,
                    &nonce[..nonce_len(self.algorithm)],
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

        let mut out = vec![0; ciphertext_and_tag.len() - tag_len(self.algorithm)];
        match &self.cipher {
            CipherInner::ChaCha20Poly1305(key) => {
                let nonce = aead::chacha20poly1305::Nonce::from_slice(nonce)
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid nonce length"))?;
                aead::chacha20poly1305::open(key, &nonce, ciphertext_and_tag, Some(&aad), &mut out)
                    .map_err(|err| {
                        io::Error::new(io::ErrorKind::Other, format!("decryption failed {err}"))
                    })?;
            }
            CipherInner::XChaCha20Poly1305(key) => {
                let nonce = aead::xchacha20poly1305::Nonce::from_slice(nonce)
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid nonce length"))?;
                aead::xchacha20poly1305::open(
                    key,
                    &nonce,
                    ciphertext_and_tag,
                    Some(&aad),
                    &mut out,
                )
                .map_err(|err| {
                    io::Error::new(io::ErrorKind::Other, format!("decryption failed {err}"))
                })?;
            }
        };
        let ciphertext = &mut ciphertext_and_tag[..out.len()];
        ciphertext.copy_from_slice(&out);

        Ok(&mut ciphertext_and_tag[..out.len()])
    }
}

pub(super) fn key_len(_: OrionAlgorithm) -> usize {
    32
}

pub(super) fn nonce_len(algorithm: OrionAlgorithm) -> usize {
    match algorithm {
        OrionAlgorithm::ChaCha20Poly1305 => 12,
        OrionAlgorithm::XChaCha20Poly1305 => 24,
    }
}

pub(super) fn tag_len(_: OrionAlgorithm) -> usize {
    16
}

#[allow(clippy::too_many_arguments)]
fn seal_in_place<'a>(
    cipher: &CipherInner,
    algorithm: OrionAlgorithm,
    plaintext: &'a mut [u8],
    block_index: Option<u64>,
    aad: Option<&[u8]>,
    nonce: &[u8],
    tag_out: &mut [u8],
    nonce_out: Option<&mut [u8]>,
) -> io::Result<&'a mut [u8]> {
    let aad = cipher::create_aad(block_index, aad);

    let mut out = vec![0; plaintext.len() + tag_len(algorithm)]; // ciphertext + tag
    match cipher {
        CipherInner::ChaCha20Poly1305(key) => {
            let nonce = aead::chacha20poly1305::Nonce::from_slice(nonce)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid nonce length"))?;
            aead::chacha20poly1305::seal(key, &nonce, plaintext, Some(&aad), &mut out).map_err(
                |err| io::Error::new(io::ErrorKind::Other, format!("decryption failed {err}")),
            )?;
        }
        CipherInner::XChaCha20Poly1305(key) => {
            let nonce = aead::xchacha20poly1305::Nonce::from_slice(nonce)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid nonce length"))?;
            aead::xchacha20poly1305::seal(key, &nonce, plaintext, Some(&aad), &mut out).map_err(
                |err| io::Error::new(io::ErrorKind::Other, format!("decryption failed {err}")),
            )?;
        }
    }
    let (ciphertext, tag) = out.split_at(plaintext.len());
    plaintext.copy_from_slice(ciphertext);

    tag_out.copy_from_slice(tag);
    nonce_out.map(|nout| {
        nout.copy_from_slice(nonce);
        nout
    });

    Ok(plaintext)
}
