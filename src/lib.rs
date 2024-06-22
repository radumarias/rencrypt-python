#![deny(warnings)]
use ::secrets::SecretVec;
use numpy::{PyArray1, PyArrayMethods};

pub use crate::cipher::CipherMeta;
pub use crate::cipher::RingAlgorithm;
pub use crate::cipher::RustCryptoAlgorithm;
use crate::cipher::{OrionAlgorithm, SodiumoxideAlgorithm};
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
use rayon::iter::IndexedParallelIterator;
use rayon::iter::ParallelIterator;
use rayon::prelude::{ParallelSlice, ParallelSliceMut};
use zeroize::Zeroize;

mod cipher;
mod crypto;
mod secrets;

/// A Python module implemented in Rust.
#[pymodule]
fn rencrypt(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Cipher>()?;
    m.add_class::<CipherMeta>()?;
    m.add_class::<RingAlgorithm>()?;
    m.add_class::<RustCryptoAlgorithm>()?;
    m.add_class::<SodiumoxideAlgorithm>()?;
    m.add_class::<OrionAlgorithm>()?;
    Ok(())
}

#[pyclass]
pub struct Cipher {
    cipher: Box<dyn cipher::Cipher>,
    cipher_meta: CipherMeta,
}

#[pymethods]
impl Cipher {
    /// The key is copied and the input key is zeroized for security reasons.
    /// The copied key will also be zeroized when the object is dropped.
    #[new]
    pub fn new(cipher_meta: CipherMeta, key: Bound<'_, PyAny>) -> PyResult<Self> {
        let key_mut = as_array_mut(&key)?;
        let key = SecretVec::<u8>::new(key_mut.len(), |s| {
            s.copy_from_slice(key_mut);
        });
        key_mut.zeroize();

        Ok(Self {
            cipher: cipher::new_cipher(cipher_meta, &key)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{}", e)))?,
            cipher_meta,
        })
    }

    pub fn seal_in_place(
        &self,
        buf: &Bound<'_, PyAny>,
        plaintext_len: usize,
        block_index: Option<u64>,
        aad: Option<&[u8]>,
        nonce: Option<&[u8]>,
    ) -> PyResult<usize> {
        let (plaintext, tag_out, nonce_out) = split_plaintext_tag_nonce_mut(
            as_array_mut(buf)?,
            plaintext_len,
            self.cipher_meta.tag_len(),
            self.cipher_meta.nonce_len(),
        );
        self.cipher
            .seal_in_place(plaintext, block_index, aad, nonce, tag_out, Some(nonce_out))?;
        Ok(plaintext_len + self.cipher_meta.overhead())
    }

    pub fn seal_in_place_from<'py>(
        &self,
        plaintext: &Bound<'py, PyAny>,
        buf: &Bound<'py, PyAny>,
        block_index: Option<u64>,
        aad: Option<&[u8]>,
        nonce: Option<&[u8]>,
    ) -> PyResult<usize> {
        let plaintext = as_array(plaintext)?;
        let buf = as_array_mut(buf)?;
        copy_slice(plaintext, buf);
        let (plaintext, tag_out, nonce_out) = split_plaintext_tag_nonce_mut(
            buf,
            plaintext.len(),
            self.cipher_meta.tag_len(),
            self.cipher_meta.nonce_len(),
        );
        self.cipher
            .seal_in_place(plaintext, block_index, aad, nonce, tag_out, Some(nonce_out))?;
        Ok(plaintext.len() + self.cipher_meta.overhead())
    }

    pub fn open_in_place(
        &mut self,
        buf: &Bound<'_, PyAny>,
        plaintext_and_tag_and_nonce_len: usize,
        block_index: Option<u64>,
        aad: Option<&[u8]>,
    ) -> PyResult<usize> {
        let buf = as_array_mut(buf)?;
        let (ciphertext_and_tag, nonce) = split_plaintext_and_tag_nonce_mut(
            buf,
            plaintext_and_tag_and_nonce_len,
            self.cipher_meta.nonce_len(),
        );
        self.cipher
            .open_in_place(ciphertext_and_tag, block_index, aad, nonce)?;
        Ok(plaintext_and_tag_and_nonce_len - self.cipher_meta.overhead())
    }

    pub fn open_in_place_from<'py>(
        &self,
        ciphertext_and_tag_and_nonce: &Bound<'py, PyAny>,
        buf: &Bound<'py, PyAny>,
        block_index: Option<u64>,
        aad: Option<&[u8]>,
    ) -> PyResult<usize> {
        let ciphertext_and_tag_and_nonce = as_array(ciphertext_and_tag_and_nonce)?;
        let buf = as_array_mut(buf)?;
        copy_slice(ciphertext_and_tag_and_nonce, buf);
        let (ciphertext_and_tag, nonce) = split_plaintext_and_tag_nonce_mut(
            buf,
            ciphertext_and_tag_and_nonce.len(),
            self.cipher_meta.nonce_len(),
        );
        let plaintext = self
            .cipher
            .open_in_place(ciphertext_and_tag, block_index, aad, nonce)?;
        Ok(plaintext.len())
    }

    #[staticmethod]
    pub fn copy_slice<'py>(src: &Bound<'py, PyAny>, buf: &Bound<'py, PyAny>) -> PyResult<()> {
        let src = as_array(src)?;
        let dst = as_array_mut(buf)?;
        copy_slice(src, dst);
        Ok(())
    }
}

fn copy_slice_internal(dst: &mut [u8], src: &[u8]) {
    dst.copy_from_slice(src);
}

fn copy_slice_concurrently(dst: &mut [u8], src: &[u8], chunk_size: usize) {
    dst.par_chunks_mut(chunk_size)
        .zip(src.par_chunks(chunk_size))
        .for_each(|(dst_chunk, src_chunk)| {
            dst_chunk.copy_from_slice(src_chunk);
        });
}

fn copy_slice(src: &[u8], dst: &mut [u8]) {
    if src.len() < 1024 * 1024 {
        let src_len = src.len();
        copy_slice_internal(&mut dst[..src_len], src);
    } else {
        copy_slice_concurrently(&mut dst[..src.len()], src, 16 * 1024);
    }
}

/// Slit plaintext__and_tag__and_nonce in (plaintext, tag, nonce)
fn split_plaintext_tag_nonce_mut(
    data: &mut [u8],
    plaintext_len: usize,
    tag_len: usize,
    nonce_len: usize,
) -> (&mut [u8], &mut [u8], &mut [u8]) {
    let (plaintext, tag_and_nonce_and_free) = data.split_at_mut(plaintext_len);
    let (tag, nonce_and_free) = tag_and_nonce_and_free.split_at_mut(tag_len);
    let (nonce, _) = nonce_and_free.split_at_mut(nonce_len);
    (plaintext, tag, nonce)
}

/// Slit plaintext__and_tag__and_nonce in (plaintext_and_tag, nonce)
fn split_plaintext_and_tag_nonce_mut(
    data: &mut [u8],
    plaintext_and_tag_and_nonce_len: usize,
    nonce_len: usize,
) -> (&mut [u8], &mut [u8]) {
    let (plaintext_and_tag, nonce_and_free) =
        data.split_at_mut(plaintext_and_tag_and_nonce_len - nonce_len);
    let (nonce, _) = nonce_and_free.split_at_mut(nonce_len);
    (plaintext_and_tag, nonce)
}

fn as_array_mut<'a>(arr: &'a Bound<PyAny>) -> PyResult<&'a mut [u8]> {
    let arr = unsafe {
        if let Ok(arr) = arr.downcast::<PyByteArray>() {
            arr.as_bytes_mut()
        } else if let Ok(arr) = arr.downcast::<PyArray1<u8>>() {
            arr.as_slice_mut().unwrap()
        } else {
            return Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
                "Expected a bytearray or numpy.array",
            ));
        }
    };
    Ok(arr)
}

fn as_array<'a>(arr: &'a Bound<PyAny>) -> PyResult<&'a [u8]> {
    let arr = unsafe {
        if let Ok(arr) = arr.downcast::<PyByteArray>() {
            arr.as_bytes()
        } else if let Ok(arr) = arr.downcast::<PyBytes>() {
            arr.as_bytes()
        } else if let Ok(arr) = arr.downcast::<PyArray1<u8>>() {
            arr.as_slice().unwrap()
        } else {
            return Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
                "Expected a PyByteArray or PyArray1<u8>",
            ));
        }
    };
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher;
    use crate::cipher::{OrionAlgorithm, SodiumoxideAlgorithm};
    use crate::crypto::create_rng;
    use crate::CipherMeta::{Orion, Ring, RustCrypto, Sodiumoxide};
    use rand_core::RngCore;
    use std::fs;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use strum::IntoEnumIterator;

    #[test]
    fn test_copy_slice_concurrently() {
        let src = b"hello";
        let mut dst = vec![0_u8; src.len()];
        copy_slice_concurrently(&mut dst, src, 16 * 1024);
        assert_eq!(dst, src);

        let mut src = [0_u8; 1024 * 1024];
        create_rng().fill_bytes(&mut src);
        let mut dst = vec![0_u8; src.len()];
        copy_slice_concurrently(&mut dst, &src, 16 * 1024);
        assert_eq!(dst, src);
    }

    #[test]
    fn test_par_chunks_mut() {
        let chunk_size = 512 * 1024;
        let mut src = [0_u8; 1024 * 1024];
        create_rng().fill_bytes(&mut src);
        let mut dst = vec![0_u8; src.len()];

        assert_eq!(
            src.len() % chunk_size,
            0,
            "Array size must be a multiple of chunk size"
        );

        dst.par_chunks_mut(chunk_size)
            .zip(src.par_chunks(chunk_size))
            .for_each(|(dst_chunk, src_chunk)| {
                dst_chunk.copy_from_slice(src_chunk);
            });

        assert_eq!(dst, src);
    }

    #[test]
    fn test_copy_slice_internal() {
        let src = b"hello";
        let mut dst = vec![0_u8; src.len()];
        copy_slice_internal(&mut dst, src);
        assert_eq!(dst, src);

        let mut src = [0_u8; 1024 * 1024];
        create_rng().fill_bytes(&mut src);
        let mut dst = vec![0_u8; src.len()];
        copy_slice_internal(&mut dst, &src);
        assert_eq!(dst, src);
    }

    fn test_seal_and_open_in_place_inner(cipher_meta: CipherMeta) {
        let key = SecretVec::new(cipher_meta.key_len(), |s| {
            create_rng().fill_bytes(s);
        });
        let cipher = cipher::new_cipher(cipher_meta, &key).unwrap();

        let message_len = 256 * 1024;
        let overhead = cipher_meta.tag_len() + cipher_meta.nonce_len();
        let mut buf = vec![0; message_len + overhead];
        let mut plaintext = vec![0; message_len];
        create_rng().fill_bytes(&mut plaintext);
        buf[..message_len].copy_from_slice(&plaintext);
        {
            let (plaintext, tag_out, nonce_out) = split_plaintext_tag_nonce_mut(
                &mut buf,
                message_len,
                cipher_meta.tag_len(),
                cipher_meta.nonce_len(),
            );
            cipher
                .seal_in_place(
                    plaintext,
                    Some(0),
                    Some(b""),
                    None,
                    tag_out,
                    Some(nonce_out),
                )
                .unwrap();
        }

        let (plaintext_and_tag, nonce_out) = split_plaintext_and_tag_nonce_mut(
            &mut buf,
            message_len + overhead,
            cipher_meta.nonce_len(),
        );
        let plaintext2 = cipher
            .open_in_place(plaintext_and_tag, Some(0), Some(b""), nonce_out)
            .unwrap();

        assert_eq!(plaintext, plaintext2);
    }

    fn test_seal_and_open_in_place_nonce_inner(cipher_meta: CipherMeta) {
        let key = SecretVec::new(cipher_meta.key_len(), |s| {
            create_rng().fill_bytes(s);
        });
        let cipher = cipher::new_cipher(cipher_meta, &key).unwrap();
        let nonce = SecretVec::new(cipher_meta.nonce_len(), |s| {
            create_rng().fill_bytes(s);
        });

        let message_len = 4096;
        let overhead = cipher_meta.tag_len() + cipher_meta.nonce_len();
        let mut buf = vec![0; message_len + overhead];
        let mut plaintext = vec![0; message_len];
        create_rng().fill_bytes(&mut plaintext);
        buf[..message_len].copy_from_slice(&plaintext);
        {
            let (plaintext, tag_out, nonce_out) = split_plaintext_tag_nonce_mut(
                &mut buf,
                message_len,
                cipher_meta.tag_len(),
                cipher_meta.nonce_len(),
            );
            cipher
                .seal_in_place(
                    plaintext,
                    Some(0),
                    Some(b""),
                    Some(&nonce.borrow()),
                    tag_out,
                    Some(nonce_out),
                )
                .unwrap();
        }

        let (plaintext_and_tag, nonce_out) = split_plaintext_and_tag_nonce_mut(
            &mut buf,
            message_len + overhead,
            cipher_meta.nonce_len(),
        );
        let plaintext2 = cipher
            .open_in_place(plaintext_and_tag, Some(0), Some(b""), nonce_out)
            .unwrap();

        assert_eq!(plaintext, plaintext2);
    }

    fn test_encrypt_no_block_index_inner(cipher_meta: CipherMeta) {
        let key = SecretVec::new(cipher_meta.key_len(), |s| {
            create_rng().fill_bytes(s);
        });
        let cipher = cipher::new_cipher(cipher_meta, &key).unwrap();

        let message_len = 4096;
        let overhead = cipher_meta.tag_len() + cipher_meta.nonce_len();
        let mut buf = vec![0; message_len + overhead];
        let mut plaintext = vec![0; message_len];
        create_rng().fill_bytes(&mut plaintext);
        buf[..message_len].copy_from_slice(&plaintext);
        {
            let (plaintext, tag_out, nonce_out) = split_plaintext_tag_nonce_mut(
                &mut buf,
                message_len,
                cipher_meta.tag_len(),
                cipher_meta.nonce_len(),
            );
            cipher
                .seal_in_place(plaintext, None, Some(b""), None, tag_out, Some(nonce_out))
                .unwrap();
        }

        let (plaintext_and_tag, nonce_out) = split_plaintext_and_tag_nonce_mut(
            &mut buf,
            message_len + overhead,
            cipher_meta.nonce_len(),
        );
        let plaintext2 = cipher
            .open_in_place(plaintext_and_tag, None, Some(b""), nonce_out)
            .unwrap();

        assert_eq!(plaintext, plaintext2);
    }

    fn test_encrypt_no_aad_inner(cipher_meta: CipherMeta) {
        let key = SecretVec::new(cipher_meta.key_len(), |s| {
            create_rng().fill_bytes(s);
        });
        let cipher = cipher::new_cipher(cipher_meta, &key).unwrap();

        let message_len = 4096;
        let overhead = cipher_meta.tag_len() + cipher_meta.nonce_len();
        let mut buf = vec![0; message_len + overhead];
        let mut plaintext = vec![0; message_len];
        create_rng().fill_bytes(&mut plaintext);
        buf[..message_len].copy_from_slice(&plaintext);
        {
            let (plaintext, tag_out, nonce_out) = split_plaintext_tag_nonce_mut(
                &mut buf,
                message_len,
                cipher_meta.tag_len(),
                cipher_meta.nonce_len(),
            );
            cipher
                .seal_in_place(plaintext, Some(0), None, None, tag_out, Some(nonce_out))
                .unwrap();
        }

        let (plaintext_and_tag, nonce_out) = split_plaintext_and_tag_nonce_mut(
            &mut buf,
            message_len + overhead,
            cipher_meta.nonce_len(),
        );
        let plaintext2 = cipher
            .open_in_place(plaintext_and_tag, Some(0), None, nonce_out)
            .unwrap();

        assert_eq!(plaintext, plaintext2);
    }

    fn test_seal_and_open_in_place_file_inner(cipher_meta: CipherMeta) {
        let buf_size = 256 * 1024;
        let key = SecretVec::new(cipher_meta.key_len(), |s| {
            create_rng().fill_bytes(s);
        });
        let cipher = cipher::new_cipher(cipher_meta, &key).unwrap();

        let file_len = 10 * 1024 * 1024;
        let overhead = cipher_meta.overhead();
        let mut plaintext = vec![0; file_len];
        create_rng().fill_bytes(&mut plaintext);
        let plaintext_path = PathBuf::from("/tmp/rencrypt-test-plaintext");
        let ciphertext_path = PathBuf::from("/tmp/rencrypt-test-ciphertext");
        let plaintext2_path = PathBuf::from("/tmp/rencrypt-test-plaintext2");
        let mut fout = File::create(plaintext_path.clone()).unwrap();
        fout.write_all(&plaintext).unwrap();
        fout.flush().unwrap();
        fout.sync_all().unwrap();

        let mut fin = File::open(plaintext_path.clone()).unwrap();
        let mut fout = File::create(ciphertext_path.clone()).unwrap();
        let mut block_index = 0;
        let mut buf = vec![0; buf_size];
        let mut nonce = vec![0; cipher_meta.nonce_len()];
        let mut tag = vec![0; cipher_meta.tag_len()];
        loop {
            let len = {
                let mut pos = 0;
                loop {
                    match fin.read(&mut buf[pos..]) {
                        Ok(read) => {
                            pos += read;
                            if read == 0 {
                                break;
                            }
                        }
                        Err(err) => panic!("{}", err),
                    }
                }
                pos
            };
            if len == 0 {
                break;
            }
            // Data to be encrypted
            let data = &mut buf[..len];

            cipher
                .seal_in_place(
                    data,
                    Some(block_index),
                    Some(b""),
                    None,
                    &mut tag,
                    Some(&mut nonce),
                )
                .unwrap();

            fout.write_all(&nonce).unwrap();
            fout.write_all(&data).unwrap();
            fout.write_all(tag.as_ref()).unwrap();
            block_index += 1;
        }
        fout.flush().unwrap();
        fout.sync_all().unwrap();

        let mut buf = vec![0; buf_size + overhead];
        let mut input = File::open(ciphertext_path.clone()).unwrap();
        let mut out = File::create(plaintext2_path.clone()).unwrap();
        block_index = 0;
        loop {
            let len = {
                let mut pos = 0;
                loop {
                    match input.read(&mut buf[pos..]) {
                        Ok(read) => {
                            pos += read;
                            if read == 0 {
                                break;
                            }
                        }
                        Err(err) => panic!("{}", err),
                    }
                }
                pos
            };
            if len == 0 {
                break;
            }
            let (nonce, ciphertext_and_tag) = buf.split_at_mut(cipher_meta.nonce_len());
            // Data to be encrypted
            let ciphertext = &mut ciphertext_and_tag[..len - cipher_meta.nonce_len()];

            let plaintext = cipher
                .open_in_place(ciphertext, Some(block_index), Some(b""), nonce)
                .unwrap();

            let _ = out.write(plaintext).unwrap();

            block_index += 1;
        }
        out.flush().unwrap();
        out.sync_all().unwrap();
        let mut plaintext2 = vec![0; file_len];
        let mut fin = File::open(plaintext2_path.clone()).unwrap();
        fin.read_exact(&mut plaintext2).unwrap();

        fs::remove_file(plaintext_path).unwrap();
        fs::remove_file(plaintext2_path).unwrap();
        fs::remove_file(ciphertext_path).unwrap();

        assert_eq!(plaintext, plaintext2);
    }

    #[test]
    fn test_seal_and_open_in_place() {
        for alg in RingAlgorithm::iter() {
            println!("RingAlgorithm {:?}", alg);
            test_seal_and_open_in_place_inner(Ring { alg });
        }
        for alg in RustCryptoAlgorithm::iter() {
            println!("RustCryptoAlgorithm {:?}", alg);
            test_seal_and_open_in_place_inner(RustCrypto { alg });
        }
        for alg in SodiumoxideAlgorithm::iter() {
            println!("SodiumoxideAlgorithm {:?}", alg);
            test_seal_and_open_in_place_inner(Sodiumoxide { alg });
        }
        for alg in OrionAlgorithm::iter() {
            println!("OrionAlgorithm {:?}", alg);
            test_seal_and_open_in_place_inner(Orion { alg });
        }
    }

    #[test]
    fn test_seal_and_open_in_place_nonce() {
        for alg in RingAlgorithm::iter() {
            println!("RingAlgorithm {:?}", alg);
            test_seal_and_open_in_place_nonce_inner(Ring { alg });
        }
        for alg in RustCryptoAlgorithm::iter() {
            println!("RustCryptoAlgorithm {:?}", alg);
            test_seal_and_open_in_place_nonce_inner(RustCrypto { alg });
        }
        for alg in SodiumoxideAlgorithm::iter() {
            println!("SodiumoxideAlgorithm {:?}", alg);
            test_seal_and_open_in_place_nonce_inner(Sodiumoxide { alg });
        }
        for alg in OrionAlgorithm::iter() {
            println!("OrionAlgorithm {:?}", alg);
            test_seal_and_open_in_place_nonce_inner(Orion { alg });
        }
    }

    #[test]
    fn test_encrypt_no_block_index() {
        for alg in RingAlgorithm::iter() {
            println!("RingAlgorithm {:?}", alg);
            test_encrypt_no_block_index_inner(Ring { alg });
        }
        for alg in RustCryptoAlgorithm::iter() {
            println!("RustCryptoAlgorithm {:?}", alg);
            test_encrypt_no_block_index_inner(RustCrypto { alg });
        }
        for alg in SodiumoxideAlgorithm::iter() {
            println!("SodiumoxideAlgorithm {:?}", alg);
            test_encrypt_no_block_index_inner(Sodiumoxide { alg });
        }
        for alg in OrionAlgorithm::iter() {
            println!("OrionAlgorithm {:?}", alg);
            test_encrypt_no_block_index_inner(Orion { alg });
        }
    }

    #[test]
    fn test_encrypt_no_aad() {
        for alg in RingAlgorithm::iter() {
            println!("RingAlgorithm {:?}", alg);
            test_encrypt_no_aad_inner(Ring { alg });
        }
        for alg in RustCryptoAlgorithm::iter() {
            println!("RustCryptoAlgorithm {:?}", alg);
            test_encrypt_no_aad_inner(RustCrypto { alg });
        }
        for alg in SodiumoxideAlgorithm::iter() {
            println!("SodiumoxideAlgorithm {:?}", alg);
            test_encrypt_no_aad_inner(Sodiumoxide { alg });
        }
        for alg in OrionAlgorithm::iter() {
            println!("OrionAlgorithm {:?}", alg);
            test_encrypt_no_aad_inner(Orion { alg });
        }
    }

    #[test]
    fn test_seal_and_open_in_place_file() {
        for alg in RingAlgorithm::iter() {
            println!("RingAlgorithm {:?}", alg);
            test_seal_and_open_in_place_file_inner(Ring { alg });
        }
        for alg in RustCryptoAlgorithm::iter() {
            println!("RustCryptoAlgorithm {:?}", alg);
            test_seal_and_open_in_place_file_inner(RustCrypto { alg });
        }
        for alg in SodiumoxideAlgorithm::iter() {
            println!("SodiumoxideAlgorithm {:?}", alg);
            test_seal_and_open_in_place_file_inner(Sodiumoxide { alg });
        }
        for alg in OrionAlgorithm::iter() {
            println!("OrionAlgorithm {:?}", alg);
            test_seal_and_open_in_place_file_inner(Orion { alg });
        }
    }
}
