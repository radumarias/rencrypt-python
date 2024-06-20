#![deny(warnings)]
use ::secrets::SecretVec;
use numpy::{PyArray1, PyArrayMethods};

pub use crate::cipher::CipherMeta;
pub use crate::cipher::RingAlgorithm;
pub use crate::cipher::RustCryptoAlgorithm;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
use rayon::iter::IndexedParallelIterator;
use rayon::iter::ParallelIterator;
use rayon::prelude::{ParallelSlice, ParallelSliceMut};
use zeroize::Zeroize;

mod cipher;
mod crypto;
mod secrets;

// 256KB seems to be the optimal block size that offers the max MB/s speed for encryption,
// on benchmarks that seem to be the case.
// We performed 10.000 encryption operations for each size varying from 64KB to 1GB,
// after 8MB it tops up to similar values.
// Const FILE_BLOCK_LEN: usize = 256 * 1024;

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
            cipher: crypto::create_cipher(cipher_meta, &key),
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

/// A Python module implemented in Rust.
#[pymodule]
fn rencrypt(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Cipher>()?;
    m.add_class::<RingAlgorithm>()?;
    m.add_class::<CipherMeta>()?;
    Ok(())
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
    use crate::crypto::create_rng;
    use crate::CipherMeta::Ring;
    use rand_core::RngCore;

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

    #[test]
    fn test_encrypt_open_in_place() {
        let cipher_meta = Ring {
            alg: RingAlgorithm::AES256GCM,
        };
        let key = SecretVec::new(cipher_meta.key_len(), |s| {
            create_rng().fill_bytes(s);
        });
        let cipher = crypto::create_cipher(cipher_meta, &key);

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
            .open_in_place(plaintext_and_tag, Some(0), Some(b""), &nonce_out)
            .unwrap();

        assert_eq!(plaintext, plaintext2);
    }
}
