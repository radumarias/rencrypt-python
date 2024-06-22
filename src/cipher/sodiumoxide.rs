use crate::cipher::{self, Cipher, SodiumoxideAlgorithm};
use crate::crypto;
use rand_core::RngCore;
use secrets::SecretVec;
use sodiumoxide::crypto::aead::*;
use std::cell::RefCell;
use std::io;
use std::sync::Mutex;

thread_local! {
    static NONCE: RefCell<Vec<u8>> = RefCell::new(vec![0;
        chacha20poly1305::NONCEBYTES
        .max(chacha20poly1305_ietf::NONCEBYTES)
        .max(xchacha20poly1305_ietf::NONCEBYTES)
        .max(aes256gcm::NONCEBYTES)
    ]);
}

#[derive(Debug)]
enum CipherInner {
    ChaCha20Poly1305(chacha20poly1305::Key),
    ChaCha20Poly1305Ietf(chacha20poly1305_ietf::Key),
    XChaCha20Poly1305Ietf(xchacha20poly1305_ietf::Key),
    // Aes256Gcm(aes256gcm::Aes256Gcm, aes256gcm::Key),
}

pub struct SodiumoxideCipher {
    cipher: CipherInner,
    rng: Mutex<Box<dyn RngCore + Send + Sync>>,
    nonce_len: usize,
}

impl SodiumoxideCipher {
    pub fn new(algorithm: SodiumoxideAlgorithm, key: &SecretVec<u8>) -> io::Result<Self> {
        let rng = Mutex::new(crypto::create_rng());
        let nonce_len = nonce_len(algorithm);
        let cipher = match algorithm {
            SodiumoxideAlgorithm::ChaCha20Poly1305 => CipherInner::ChaCha20Poly1305(
                chacha20poly1305::Key::from_slice(&key.borrow()).ok_or(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid key length",
                ))?,
            ),
            SodiumoxideAlgorithm::ChaCha20Poly1305Ieft => CipherInner::ChaCha20Poly1305Ietf(
                chacha20poly1305_ietf::Key::from_slice(&key.borrow()).ok_or(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid key length",
                ))?,
            ),
            SodiumoxideAlgorithm::XChaCha20Poly1305Ieft => CipherInner::XChaCha20Poly1305Ietf(
                xchacha20poly1305_ietf::Key::from_slice(&key.borrow()).ok_or(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid key length",
                ))?,
            ),
            // SodiumoxideAlgorithm::Aes256Gcm => CipherInner::Aes256Gcm(
            //     aes256gcm::Aes256Gcm::new()
            //         .map_err(|_| io::Error::new(io::ErrorKind::Other, "cannot create cipher"))?,
            //     aes256gcm::Key::from_slice(&key.borrow()).ok_or(
            //                     io::Error::new(io::ErrorKind::InvalidInput, "invalid key length"))?
            //             ),
        };

        Ok(Self {
            cipher,
            rng,
            nonce_len,
        })
    }
}

impl Cipher for SodiumoxideCipher {
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
        let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(ciphertext_and_tag.len() - 16);

        match &self.cipher {
            CipherInner::ChaCha20Poly1305(key) => {
                chacha20poly1305::open_detached(
                    ciphertext,
                    Some(&aad),
                    &chacha20poly1305::Tag::from_slice(tag).ok_or(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid tag length",
                    ))?,
                    &chacha20poly1305::Nonce::from_slice(nonce).ok_or(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid nonce length",
                    ))?,
                    key,
                )
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "decryption failed"))?;
            }
            CipherInner::ChaCha20Poly1305Ietf(key) => {
                chacha20poly1305_ietf::open_detached(
                    ciphertext,
                    Some(&aad),
                    &chacha20poly1305_ietf::Tag::from_slice(tag).ok_or(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid tag length",
                    ))?,
                    &chacha20poly1305_ietf::Nonce::from_slice(nonce).ok_or(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid nonce length",
                    ))?,
                    key,
                )
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "decryption failed"))?;
            }
            CipherInner::XChaCha20Poly1305Ietf(key) => {
                xchacha20poly1305_ietf::open_detached(
                    ciphertext,
                    Some(&aad),
                    &xchacha20poly1305_ietf::Tag::from_slice(tag).ok_or(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid tag length",
                    ))?,
                    &xchacha20poly1305_ietf::Nonce::from_slice(nonce).ok_or(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid nonce length",
                    ))?,
                    key,
                )
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "decryption failed"))?;
            } // CipherInner::Aes256Gcm(cipher, key) => {
              //     cipher
              //         .open_detached(
              //             ciphertext,
              //             Some(&aad),
              //             &aes256gcm::Tag::from_slice(tag).ok_or(io::Error::new(io::ErrorKind::InvalidData, "invalid tag length"))?,
              //             &aes256gcm::Nonce::from_slice(nonce).ok_or(io::Error::new(io::ErrorKind::InvalidData, "invalid nonce length"))?,
              //             key,
              //         )
              //         .map_err(|_| io::Error::new(io::ErrorKind::Other, "decryption failed"))?;
              // }
        };

        Ok(ciphertext)
    }
}

pub(super) fn key_len(algorithm: SodiumoxideAlgorithm) -> usize {
    match algorithm {
        SodiumoxideAlgorithm::ChaCha20Poly1305 => {
            sodiumoxide::crypto::aead::chacha20poly1305::KEYBYTES
        }
        SodiumoxideAlgorithm::ChaCha20Poly1305Ieft => {
            sodiumoxide::crypto::aead::chacha20poly1305_ietf::KEYBYTES
        }
        SodiumoxideAlgorithm::XChaCha20Poly1305Ieft => {
            sodiumoxide::crypto::aead::xchacha20poly1305_ietf::KEYBYTES
        } // SodiumoxideAlgorithm::Aes256Gcm => sodiumoxide::crypto::aead::aes256gcm::KEYBYTES,
    }
}

pub(super) fn nonce_len(algorithm: SodiumoxideAlgorithm) -> usize {
    match algorithm {
        SodiumoxideAlgorithm::ChaCha20Poly1305 => {
            sodiumoxide::crypto::aead::chacha20poly1305::NONCEBYTES
        }
        SodiumoxideAlgorithm::ChaCha20Poly1305Ieft => {
            sodiumoxide::crypto::aead::chacha20poly1305_ietf::NONCEBYTES
        }
        SodiumoxideAlgorithm::XChaCha20Poly1305Ieft => {
            sodiumoxide::crypto::aead::xchacha20poly1305_ietf::NONCEBYTES
        } // SodiumoxideAlgorithm::Aes256Gcm => sodiumoxide::crypto::aead::aes256gcm::NONCEBYTES,
    }
}

pub(super) fn tag_len(algorithm: SodiumoxideAlgorithm) -> usize {
    match algorithm {
        SodiumoxideAlgorithm::ChaCha20Poly1305 => {
            sodiumoxide::crypto::aead::chacha20poly1305::TAGBYTES
        }
        SodiumoxideAlgorithm::ChaCha20Poly1305Ieft => {
            sodiumoxide::crypto::aead::chacha20poly1305_ietf::TAGBYTES
        }
        SodiumoxideAlgorithm::XChaCha20Poly1305Ieft => {
            sodiumoxide::crypto::aead::xchacha20poly1305_ietf::TAGBYTES
        } // SodiumoxideAlgorithm::Aes256Gcm => sodiumoxide::crypto::aead::aes256gcm::TAGBYTES,
    }
}

fn seal_in_place<'a>(
    cipher: &CipherInner,
    plaintext: &'a mut [u8],
    block_index: Option<u64>,
    aad: Option<&[u8]>,
    nonce: &[u8],
    tag_out: &mut [u8],
    nonce_out: Option<&mut [u8]>,
) -> io::Result<&'a mut [u8]> {
    let aad = cipher::create_aad(block_index, aad);

    let tag = match cipher {
        CipherInner::ChaCha20Poly1305(key) => {
            chacha20poly1305::seal_detached(
                plaintext,
                Some(&aad),
                &chacha20poly1305::Nonce::from_slice(nonce).ok_or(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid nonce length",
                ))?,
                key,
            )
            .0
        }
        CipherInner::ChaCha20Poly1305Ietf(key) => {
            chacha20poly1305_ietf::seal_detached(
                plaintext,
                Some(&aad),
                &chacha20poly1305_ietf::Nonce::from_slice(nonce).ok_or(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid nonce length",
                ))?,
                key,
            )
            .0
        }
        CipherInner::XChaCha20Poly1305Ietf(key) => {
            xchacha20poly1305_ietf::seal_detached(
                plaintext,
                Some(&aad),
                &xchacha20poly1305_ietf::Nonce::from_slice(nonce).ok_or(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid nonce length",
                ))?,
                key,
            )
            .0
        } // CipherInner::Aes256Gcm(cipher, key) => {
          //     cipher
          //         .seal_detached(
          //             plaintext,
          //             Some(&aad),
          //             &aes256gcm::Nonce::from_slice(nonce).ok_or(io::Error::new(io::ErrorKind::InvalidData,
          // "invalid nonce length"))?,
          //             key,
          //         )
          //         .0
          // }
    };

    tag_out.copy_from_slice(&tag);
    nonce_out.map(|nout| {
        nout.copy_from_slice(nonce);
        nout
    });

    Ok(plaintext)
}
