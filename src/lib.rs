mod encryptor;

use std::io::{Read, Seek, Write};
use std::sync::{Arc, Mutex};

use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use rayon::iter::IndexedParallelIterator;
use rayon::iter::ParallelIterator;
use rayon::prelude::{ParallelSlice, ParallelSliceMut};
use ring::aead::{Aad, AES_256_GCM, BoundKey, CHACHA20_POLY1305, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey};
use ring::error::Unspecified;
use zeroize::Zeroize;

// 256KB seems to be the optimal block size that offers the max MB/s speed for encryption,
// on benchmarks that seem to be the case.
// We performed 10.000 encryption operations for each size varying from 64KB to 1GB,
// after 8MB it tops up to similar values.
const FILE_BLOCK_LEN: usize = 128 * 1024;

#[pyclass]
#[derive(Debug, Clone, Copy)]
pub enum Provider {
    Ring,
    RustCrypto,
}

#[pyclass]
#[derive(Debug, Clone, Copy)]
pub enum Cipher {
    ChaCha20Poly1305,
    AES256GCM,
}

#[pymethods]
impl Cipher {
    /// In bytes.
    #[must_use]
    #[allow(clippy::use_self)]
    #[pyo3(signature = ())]
    pub fn key_len(&self) -> usize {
        match self {
            Cipher::ChaCha20Poly1305 => 32,
            Cipher::AES256GCM => 32,
        }
    }

    /// Max length (in bytes) of the plaintext that can be encrypted before becoming unsafe.
    #[must_use]
    #[allow(clippy::use_self)]
    #[pyo3(signature = ())]
    pub const fn max_plaintext_len(&self) -> usize {
        match self {
            Cipher::ChaCha20Poly1305 => (2_usize.pow(32) - 1) * 64,
            Cipher::AES256GCM => (2_usize.pow(39) - 256) / 8,
        }
    }

    pub fn generate_key<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyByteArray>> {
        let mut rng = create_rng();
        let mut key = vec![0; self.key_len()];
        rng.fill_bytes(&mut key);
        Ok(PyByteArray::new_bound(py, key.as_slice()))
    }
}

#[pyclass]
pub struct REncrypt {
    provider: Provider,
    cipher: Cipher,
    sealing_key: Arc<Mutex<SealingKey<RandomNonceSequenceWrapper>>>,
    nonce_sequence: Arc<Mutex<RandomNonceSequence>>,
    last_nonce: Arc<Mutex<Vec<u8>>>,
    opening_key: Arc<Mutex<OpeningKey<ExistingNonceSequence>>>,
    key: Vec<u8>,
}

#[pymethods]
impl REncrypt {
    /// The key is copied and the input key is zeroized for security reasons.
    /// The copied key will also be zeroized when the object is dropped.
    #[new]
    pub fn new<'py>(cipher: Cipher, key: Bound<'py, PyByteArray>) -> Self {
        let key_copy = unsafe { key.as_bytes().to_vec() };
        unsafe { key.as_bytes_mut().zeroize(); }
        // todo: expose other providers
        let provider = Provider::Ring;
        let key = key_copy;

        let (sealing_key, nonce_sequence) = create_sealing_key(provider, cipher, &key);
        let (opening_key, last_nonce) = create_opening_key(provider, cipher, &key);

        Self {
            provider,
            cipher,
            sealing_key: Arc::new(Mutex::new(sealing_key)),
            nonce_sequence,
            last_nonce,
            opening_key: Arc::new(Mutex::new(opening_key)),
            key,
        }
    }

    pub fn create_buf<'py>(&'py self, py: Python<'py>, block_len: usize) -> (usize, usize, Bound<'py, PyByteArray>) {
        let overhead = self.overhead();
        let buf = vec![0_u8; block_len + overhead];
        (buf.len() - overhead, buf.len(), PyByteArray::new_bound(py, &buf))
    }

    pub fn overhead(&self) -> usize {
        self.get_tag_len() + self.get_nonce_len()
    }

    pub fn encrypt<'py>(&self, buf: &Bound<'py, PyByteArray>, plaintext_len: usize, block_index: u64, aad: &[u8]) -> PyResult<usize> {
        let data = unsafe { buf.as_bytes_mut() };
        let (plaintext, tag_out, nonce_out) = split_plaintext_tag_nonce_mut(data, plaintext_len, self.get_tag_len(), self.get_nonce_len());
        encrypt(plaintext, block_index, aad, self.sealing_key.clone(), self.nonce_sequence.clone(), tag_out, nonce_out);
        Ok(plaintext_len + self.overhead())
    }

    pub fn encrypt_into<'py>(&self, plaintext: &[u8], ciphertext: &Bound<'py, PyByteArray>, block_index: u64, aad: &[u8]) -> PyResult<usize> {
        let data = unsafe { ciphertext.as_bytes_mut() };
        copy_slice(plaintext, data);
        let (plaintext, tag_out, nonce_out) = split_plaintext_tag_nonce_mut(data, plaintext.len(), self.get_tag_len(), self.get_nonce_len());
        encrypt(plaintext, block_index, aad, self.sealing_key.clone(), self.nonce_sequence.clone(), tag_out, nonce_out);
        Ok(plaintext.len() + self.overhead())
    }

    pub fn encrypt_into1<'py>(&self, plaintext: &Bound<'py, PyByteArray>, ciphertext: &Bound<'py, PyByteArray>, block_index: u64, aad: &[u8]) -> PyResult<usize> {
        let data = unsafe { ciphertext.as_bytes_mut() };
        unsafe { copy_slice(plaintext.as_bytes(), data); }
        let (plaintext, tag_out, nonce_out) = split_plaintext_tag_nonce_mut(data, plaintext.len(), self.get_tag_len(), self.get_nonce_len());
        encrypt(plaintext, block_index, aad, self.sealing_key.clone(), self.nonce_sequence.clone(), tag_out, nonce_out);
        Ok(plaintext.len() + self.overhead())
    }

    pub fn encrypt_from<'py>(&mut self, plaintext: &[u8], block_index: u64, aad: &[u8], py: Python<'py>) -> PyResult<Bound<'py, PyByteArray>> {
        let mut data = vec![0; plaintext.len() + self.overhead()];
        copy_slice(plaintext, &mut data);
        let (plaintext, tag_out, nonce_out) = split_plaintext_tag_nonce_mut(&mut data, plaintext.len(), self.get_tag_len(), self.get_nonce_len());
        encrypt(plaintext, block_index, aad, self.sealing_key.clone(), self.nonce_sequence.clone(), tag_out, nonce_out);
        Ok(PyByteArray::new_bound(py, data.as_slice()))
    }

    pub fn encrypt_from1<'py>(&mut self, plaintext: &Bound<'py, PyByteArray>, block_index: u64, aad: &[u8], py: Python<'py>) -> PyResult<Bound<'py, PyByteArray>> {
        let mut data = vec![0; plaintext.len() + self.overhead()];
        unsafe { copy_slice(plaintext.as_bytes(), &mut data); }
        let (plaintext, tag_out, nonce_out) = split_plaintext_tag_nonce_mut(&mut data, plaintext.len(), self.get_tag_len(), self.get_nonce_len());
        encrypt(plaintext, block_index, aad, self.sealing_key.clone(), self.nonce_sequence.clone(), tag_out, nonce_out);
        Ok(PyByteArray::new_bound(py, data.as_slice()))
    }

    // #[cfg(target_os = "linux")]
    // pub fn encrypt_file(&mut self, src: &str, dst: &str, aad: &[u8]) -> PyResult<()> {
    //     // if File::open(src).unwrap().metadata().unwrap().len() < 128 * 1024 * 1024 {
    //     // self.encrypt_file_uring_seq(src, dst, aad)
    //     // } else {
    //     //     self.encrypt_file_uring_par(src, dst, aad)
    //     // }
    // }
    //
    // fn encrypt_file_uring_seq(&mut self, src: &str, dst: &str, aad: &[u8]) -> PyResult<()> {
    //     tokio_uring::start(async {
    //         let tag_len = self.get_tag_len();
    //         let nonce_len = self.get_nonce_len();
    //         let mut block_index = 0_u64;
    //         let overhead = self.overhead();
    //
    //         // Open the source file for reading
    //         let src_file = tokio_uring::fs::File::open(src).await.unwrap();
    //
    //         // Open or create the destination file for writing
    //         let dst_file = tokio_uring::fs::OpenOptions::new()
    //             .write(true)
    //             .create(true)
    //             .open(dst).await.unwrap();
    //
    //         let mut buf = vec![0u8; FILE_BLOCK_LEN];
    //         let mut offset_read = 0;
    //         let mut offset_write = 0;
    //         let mut tag_out = vec![0u8; tag_len];
    //         let mut nonce_out = vec![0u8; nonce_len];
    //         loop {
    //             let len = {
    //                 // try to read a chunk from the source file
    //                 let res = src_file.read_exact_at(buf, offset_read).await;
    //                 if res.0.is_err() {
    //                     // we're at the end of the file, read remaining
    //                     let (len, read_buf) = src_file.read_at(res.1, offset_read).await;
    //                     let len = len.unwrap();
    //                     buf = read_buf;
    //                     offset_read += len as u64;
    //                     len
    //                 } else {
    //                     buf = res.1;
    //                     offset_read += buf.len() as u64;
    //                     buf.len()
    //                 }
    //             };
    //             if len == 0 {
    //                 break; // End of file reached
    //             }
    //
    //             // encrypt
    //             // encrypt(&mut buf, block_index, &aad, self.sealing_key.clone(), self.nonce_sequence.clone(), &mut tag_out, &mut nonce_out);
    //
    //             // Write the chunk to the destination file
    //             // todo: try to do it without clone
    //             // let res = dst_file.write_all_at(buf, offset_write).await;
    //             // res.0.unwrap();
    //             // buf = res.1;
    //             offset_write += len as u64 + overhead as u64;
    //             // let res = dst_file.write_all_at(tag_out, offset_write).await;
    //             // res.0.unwrap();
    //             // tag_out = res.1;
    //             // offset_write += tag_len as u64;
    //             // let res = dst_file.write_all_at(nonce_out, offset_write).await;
    //             // res.0.unwrap();
    //             // nonce_out = res.1;
    //             // offset_write += nonce_len as u64;
    //
    //             if len < buf.len() {
    //                 // eof
    //                 break;
    //             }
    //
    //             block_index += 1;
    //         }
    //         dst_file.sync_all().await.unwrap();
    //         File::open(Path::new(dst).to_path_buf().parent().expect("oops, we don't have parent")).unwrap().sync_all().unwrap();
    //     });
    //
    //     Ok(())
    // }

    // fn encrypt_file_uring_par(&mut self, src: &str, dst: &str, aad: &[u8]) -> PyResult<()> {
    //     let tag_len = self.get_tag_len();
    //     let nonce_len = self.get_nonce_len();
    //     let provider = self.provider;
    //     let cipher = self.cipher;
    //     let key = &self.key;
    //
    //     let overhead = self.overhead();
    //     let block_len = FILE_BLOCK_LEN;
    //
    //     let fin = File::open(src).unwrap();
    //     let file_size = fin.metadata().unwrap().len();
    //
    //     {
    //         // create out file with preallocated size
    //         let fout = File::create(dst).unwrap();
    //         fout.set_len(file_size + (file_size / block_len as u64 + 1) * self.overhead() as u64).unwrap();
    //         fout.sync_all().unwrap();
    //         File::open(Path::new(dst).to_path_buf().parent().expect("oops, we don't have parent")).unwrap().sync_all().unwrap();
    //     }
    //
    //     let bufs = vec![
    //         (Mutex::new(false), Mutex::new(vec![0u8; block_len])),
    //         (Mutex::new(false), Mutex::new(vec![0u8; block_len])),
    //         (Mutex::new(false), Mutex::new(vec![0u8; block_len])),
    //         (Mutex::new(false), Mutex::new(vec![0u8; block_len])),
    //         (Mutex::new(false), Mutex::new(vec![0u8; block_len])),
    //         (Mutex::new(false), Mutex::new(vec![0u8; block_len])),
    //         (Mutex::new(false), Mutex::new(vec![0u8; block_len])),
    //         (Mutex::new(false), Mutex::new(vec![0u8; block_len])),
    //         (Mutex::new(false), Mutex::new(vec![0u8; block_len])),
    //         (Mutex::new(false), Mutex::new(vec![0u8; block_len])),
    //         (Mutex::new(false), Mutex::new(vec![0u8; block_len])),
    //     ];
    //
    //     let chunks: Vec<(u64, usize)> = (0..file_size)
    //         .step_by(block_len)
    //         .map(|offset| {
    //             let end = std::cmp::min(offset + block_len as u64, file_size);
    //             (offset, (end - offset) as usize)
    //         })
    //         .collect();
    //     chunks.par_iter().for_each(|&(offset, length)| {
    //         let src_clone = src.to_string();
    //         let dst_clone = dst.to_string();
    //         tokio_uring::start(async {
    //             let mut buf = None;
    //             let mut guard = None;
    //             'outer: loop {
    //                 for (lock, vec) in &bufs {
    //                     let res = lock.try_lock();
    //                     if res.is_err() {
    //                         continue;
    //                     } else {
    //                         guard = Some(res.unwrap());
    //                         buf = Some(vec);
    //                         break 'outer;
    //                     }
    //                 }
    //             }
    //
    //             // read
    //             // Open the source file for reading
    //             let src_file = tokio_uring::fs::File::open(src_clone).await.unwrap();
    //             // Read a chunk from the source file
    //             let mut buf = vec![0u8; length];
    //             let res = src_file.read_exact_at(&mut buf, offset).await;
    //             res.0.unwrap();
    //             let mut buf = res.1;
    //
    //             // encrypt
    //             let (sealing_key, nonce_sequence) = create_sealing_key(provider, cipher, &key);
    //             let mut tag = vec![0u8; tag_len];
    //             let mut nonce = vec![0u8; nonce_len];
    //             let block_index = offset / block_len as u64;
    //             encrypt(&mut buf, block_index, &aad, Arc::new(Mutex::new(sealing_key)), nonce_sequence.clone(), &mut tag, &mut nonce);
    //
    //             // Open or create the destination file for writing
    //             let dst_file = tokio_uring::fs::OpenOptions::new()
    //                 .write(true)
    //                 .create(true)
    //                 .open(dst).await.unwrap();
    //             // write
    //             let mut ciphertext_ofset = offset + block_index * overhead as u64;
    //             // let res = dst_file.write_all_at(buf, ciphertext_ofset).await;
    //             // res.0.unwrap();
    //             // buf = res.1;
    //             ciphertext_ofset += length as u64;
    //             // dst_file.write_all_at(&tag, ciphertext_ofset).await.expect("Unable to write tag to destination file");
    //             // ciphertext_ofset += tag_len as u64;
    //             // dst_file.write_all_at(&nonce, ciphertext_ofset).await.expect("Unable to write nonce to destination file");
    //             dst_file.sync_all().await.expect("Unable to sync destination file");
    //         });
    //     });
    //
    //     let fout = File::open(dst).unwrap();
    //     fout.sync_all().unwrap();
    //     File::open(Path::new(dst).to_path_buf().parent().expect("oops, we don't have parent")).unwrap().sync_all().unwrap();
    //
    //     Ok(())
    // }

    pub fn decrypt<'py>(&mut self, buf: &Bound<'py, PyByteArray>, plaintext_and_tag_len: usize, block_index: u64, aad: &[u8]) -> PyResult<usize> {
        let data = unsafe { buf.as_bytes_mut() };
        let (ciphertext_and_tag, nonce) = split_plaintext_and_tag_nonce_mut(data, plaintext_and_tag_len, self.get_nonce_len());
        decrypt(ciphertext_and_tag, block_index, aad, self.opening_key.clone(), self.last_nonce.clone(), nonce);
        Ok(plaintext_and_tag_len - self.overhead())
    }

    pub fn decrypt_into<'py>(&self, ciphertext_and_tag_and_nonce: &[u8], plaintext: &Bound<'py, PyByteArray>, block_index: u64, aad: &[u8]) -> PyResult<usize> {
        let data = unsafe { plaintext.as_bytes_mut() };
        copy_slice(ciphertext_and_tag_and_nonce, data);
        let (ciphertext_and_tag, nonce) = split_plaintext_and_tag_nonce_mut(data, ciphertext_and_tag_and_nonce.len(), self.get_nonce_len());
        let plaintext = decrypt(ciphertext_and_tag, block_index, aad, self.opening_key.clone(), self.last_nonce.clone(), nonce);
        Ok(plaintext.len())
    }

    pub fn decrypt_into1<'py>(&self, ciphertext_and_tag_and_nonce: &Bound<'py, PyByteArray>, plaintext: &Bound<'py, PyByteArray>, block_index: u64, aad: &[u8]) -> PyResult<usize> {
        let data = unsafe { plaintext.as_bytes_mut() };
        unsafe { copy_slice(ciphertext_and_tag_and_nonce.as_bytes(), data); }
        let (ciphertext_and_tag, nonce) = split_plaintext_and_tag_nonce_mut(data, ciphertext_and_tag_and_nonce.len(), self.get_nonce_len());
        let plaintext = decrypt(ciphertext_and_tag, block_index, aad, self.opening_key.clone(), self.last_nonce.clone(), nonce);
        Ok(plaintext.len())
    }

    pub fn decrypt_from<'py>(&self, py: Python<'py>, ciphertext_and_tag_and_nonce: &[u8], block_index: u64, aad: &[u8]) -> PyResult<Bound<'py, PyByteArray>> {
        let mut data = vec![0_u8; ciphertext_and_tag_and_nonce.len()];
        copy_slice(ciphertext_and_tag_and_nonce, &mut data);
        let (ciphertext_and_tag, nonce) = split_plaintext_and_tag_nonce_mut(&mut data, ciphertext_and_tag_and_nonce.len(), self.get_nonce_len());
        let plaintext = decrypt(ciphertext_and_tag, block_index, aad, self.opening_key.clone(), self.last_nonce.clone(), nonce);
        Ok(PyByteArray::new_bound(py, &plaintext))
    }

    pub fn decrypt_from1<'py>(&self, py: Python<'py>, ciphertext_and_tag_and_nonce: &Bound<'py, PyByteArray>, block_index: u64, aad: &[u8]) -> PyResult<Bound<'py, PyByteArray>> {
        let mut data = vec![0_u8; ciphertext_and_tag_and_nonce.len()];
        unsafe { copy_slice(ciphertext_and_tag_and_nonce.as_bytes(), &mut data); }
        let (ciphertext_and_tag, nonce) = split_plaintext_and_tag_nonce_mut(&mut data, ciphertext_and_tag_and_nonce.len(), self.get_nonce_len());
        let plaintext = decrypt(ciphertext_and_tag, block_index, aad, self.opening_key.clone(), self.last_nonce.clone(), nonce);
        Ok(PyByteArray::new_bound(py, &plaintext))
    }

    // pub fn decrypt_file(&mut self, src: &str, dst: &str, aad: &[u8]) -> PyResult<()> {
    //     let nonce_len = self.get_nonce_len();
    //     let provider = self.provider;
    //     let cipher = self.cipher;
    //     let key = &self.key;
    //
    //     let overhead = self.overhead();
    //     let block_len = FILE_BLOCK_LEN + overhead;
    //
    //     let fin = File::open(src).unwrap();
    //     let ciphertext_file_size = fin.metadata().unwrap().len();
    //     let plaintext_file_size = ciphertext_file_size - (ciphertext_file_size / block_len as u64 + 1) * self.overhead() as u64;
    //
    //     {
    //         // create out file with preallocated size
    //         let fout = File::create(dst).unwrap();
    //         fout.set_len(plaintext_file_size).unwrap();
    //         fout.sync_all().unwrap();
    //         File::open(Path::new(dst).to_path_buf().parent().expect("oops, we don't have parent")).unwrap().sync_all().unwrap();
    //     }
    //
    //     let chunks: Vec<(u64, usize)> = (0..ciphertext_file_size)
    //         .step_by(block_len)
    //         .map(|offset| {
    //             let end = std::cmp::min(offset + block_len as u64, ciphertext_file_size);
    //             (offset, (end - offset) as usize)
    //         })
    //         .collect();
    //     chunks.par_iter().for_each(|&(offset, length)| {
    //         // read
    //         let mut buf = vec![0u8; length];
    //         let mut src_file = BufReader::new(File::open(src).expect("Unable to open source file"));
    //         src_file.seek(SeekFrom::Start(offset)).expect("Unable to seek in source file");
    //         src_file.read_exact(&mut buf).expect("Unable to read chunk from source file");
    //
    //         // decrypt
    //         let (opening_key, last_nonce) = create_opening_key(provider, cipher, &key);
    //         let block_index = offset / block_len as u64;
    //         let (ciphertext_and_tag, nonce) = buf.split_at_mut(length - nonce_len);
    //         decrypt(ciphertext_and_tag, block_index, &aad, Arc::new(Mutex::new(opening_key)), last_nonce.clone(), nonce);
    //
    //         // write
    //         let mut dst_file = BufWriter::new(OpenOptions::new().write(true).open(dst).expect("Unable to open destination file"));
    //         dst_file.seek(SeekFrom::Start(offset - block_index * overhead as u64)).expect("Unable to seek in destination file");
    //         dst_file.write_all(&buf[..length - overhead]).expect("Unable to write chunk to destination file");
    //         dst_file.flush().expect("Unable to flush destination file");
    //         dst_file.into_inner().unwrap().sync_all().expect("Unable to sync destination file");
    //
    //         buf.zeroize();
    //     });
    //
    //     let fout = File::open(dst).unwrap();
    //     fout.sync_all().unwrap();
    //     File::open(Path::new(dst).to_path_buf().parent().expect("oops, we don't have parent")).unwrap().sync_all().unwrap();
    //
    //     Ok(())
    // }

    #[staticmethod]
    pub fn copy_slice<'py>(src: &[u8], buf: &Bound<'py, PyByteArray>) -> PyResult<()> {
        let data = unsafe { buf.as_bytes_mut() };
        copy_slice(src, data);
        Ok(())
    }

    #[staticmethod]
    pub fn copy_slice1<'py>(src: &Bound<'py, PyByteArray>, buf: &Bound<'py, PyByteArray>) -> PyResult<()> {
        let src = unsafe { src.as_bytes() };
        let data = unsafe { buf.as_bytes_mut() };
        copy_slice(src, data);
        Ok(())
    }

    pub fn get_nonce_len(&self) -> usize {
        get_nonce_len(self.provider, self.cipher)
    }

    pub fn get_tag_len(&self) -> usize {
        get_tag_len(self.provider, self.cipher)
    }

    #[staticmethod]
    pub fn zeroize<'py>(arr: &Bound<'py, PyByteArray>) -> PyResult<()> {
        let arr = unsafe { arr.as_bytes_mut() };
        arr.zeroize();

        Ok(())
    }
}

impl Drop for REncrypt {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// A Python module implemented in Rust.
#[pymodule]
fn rencrypt<'py>(_py: Python, m: &Bound<'py, PyModule>) -> PyResult<()> {
    m.add_class::<REncrypt>()?;
    m.add_class::<Cipher>()?;
    Ok(())
}

pub struct RandomNonceSequence {
    rng: Box<dyn RngCore + Send + Sync>,
    last_nonce: Vec<u8>,
}

impl RandomNonceSequence {
    pub fn new(nonce_len: usize) -> Self {
        Self {
            rng: Box::new(create_rng()),
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

#[must_use]
pub fn create_rng() -> impl RngCore + CryptoRng {
    ChaCha20Rng::from_entropy()
}

struct RandomNonceSequenceWrapper {
    inner: Arc<Mutex<RandomNonceSequence>>,
}

impl RandomNonceSequenceWrapper {
    pub fn new(inner: Arc<Mutex<RandomNonceSequence>>) -> Self {
        Self { inner }
    }
}

impl NonceSequence for RandomNonceSequenceWrapper {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.inner.lock().unwrap().advance()
    }
}

fn copy_slice_internal(dst: &mut [u8], src: &[u8]) {
    dst.copy_from_slice(&src);
}

fn copy_slice_concurrently(dst: &mut [u8], src: &[u8], chunk_size: usize) {
    dst.par_chunks_mut(chunk_size).zip(src.par_chunks(chunk_size)).for_each(|(dst_chunk, src_chunk)| {
        dst_chunk.copy_from_slice(src_chunk);
    });
}

fn get_ring_algorithm(cipher: Cipher) -> &'static ring::aead::Algorithm {
    match cipher {
        Cipher::ChaCha20Poly1305 => &CHACHA20_POLY1305,
        Cipher::AES256GCM => &AES_256_GCM,
    }
}

fn encrypt(plaintext: &mut [u8], block_index: u64, aad: &[u8],
           sealing_key: Arc<Mutex<SealingKey<RandomNonceSequenceWrapper>>>, nonce_sequence: Arc<Mutex<RandomNonceSequence>>,
           tag_out: &mut [u8], nonce_out: &mut [u8]) {
    // lock here to keep the lock while encrypting
    let mut sealing_key = sealing_key.lock().unwrap();

    let block_index_bytes = block_index.to_le_bytes();
    let mut aad2 = vec![0; aad.len() + 8];
    aad2[..aad.len()].copy_from_slice(aad);
    aad2[aad.len()..].copy_from_slice(&block_index_bytes);
    let aad = Aad::<&[u8]>::from(aad2.as_ref());

    let tag = sealing_key.seal_in_place_separate_tag(aad, plaintext).unwrap();

    tag_out.copy_from_slice(tag.as_ref());
    nonce_out.copy_from_slice(&nonce_sequence.lock().unwrap().last_nonce);
}

fn decrypt<'a>(ciphertext_and_tag: &'a mut [u8], block_index: u64, aad: &[u8], opening_key: Arc<Mutex<OpeningKey<ExistingNonceSequence>>>,
               last_nonce: Arc<Mutex<Vec<u8>>>, nonce: &[u8]) -> &'a mut [u8] {
    // lock here to keep the lock while decrypting
    let mut opening_key = opening_key.lock().unwrap();

    last_nonce.lock().unwrap().copy_from_slice(nonce);

    let block_index_bytes = block_index.to_le_bytes();
    let mut aad2 = vec![0; aad.len() + 8];
    aad2[..aad.len()].copy_from_slice(aad);
    aad2[aad.len()..].copy_from_slice(&block_index_bytes);
    let aad = Aad::<&[u8]>::from(aad2.as_ref());

    let plaintext = opening_key.open_within(aad, ciphertext_and_tag, 0..).unwrap();
    plaintext
}

fn copy_slice(src: &[u8], dst: &mut [u8]) {
    if src.len() < 1024 * 1024 {
        let src_len = src.len();
        copy_slice_internal(&mut dst[..src_len], src);
    } else {
        copy_slice_concurrently(&mut dst[..src.len()], src, 16 * 1024);
    }
}

fn create_sealing_key(provider: Provider, cipher: Cipher, key: &Vec<u8>) -> (SealingKey<RandomNonceSequenceWrapper>, Arc<Mutex<RandomNonceSequence>>) {
    // Create a new NonceSequence type which generates nonces
    let nonce_seq = Arc::new(Mutex::new(RandomNonceSequence::new(get_nonce_len(provider, cipher))));
    let nonce_sequence = nonce_seq.clone();
    let nonce_wrapper = RandomNonceSequenceWrapper::new(nonce_seq.clone());
    // Create a new AEAD key without a designated role or nonce sequence
    let unbound_key = UnboundKey::new(get_ring_algorithm(cipher), key).unwrap();

    // Create a new AEAD key for encrypting and signing ("sealing"), bound to a nonce sequence
    // The SealingKey can be used multiple times, each time a new nonce will be used
    let sealing_key = SealingKey::new(unbound_key, nonce_wrapper);
    (sealing_key, nonce_sequence)
}

fn create_opening_key(provider: Provider, cipher: Cipher, key: &Vec<u8>) -> (OpeningKey<ExistingNonceSequence>, Arc<Mutex<Vec<u8>>>) {
    let last_nonce = Arc::new(Mutex::new(vec![0_u8; get_nonce_len(provider, cipher)]));
    let unbound_key = UnboundKey::new(get_ring_algorithm(cipher), key).unwrap();
    let nonce_sequence = ExistingNonceSequence::new(last_nonce.clone());
    let opening_key = OpeningKey::new(unbound_key, nonce_sequence);
    (opening_key, last_nonce)
}

pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn get_nonce_len(provider: Provider, cipher: Cipher) -> usize {
    match provider {
        Provider::Ring => get_ring_algorithm(cipher).nonce_len(),
        Provider::RustCrypto => {
            todo!()
        }
    }
}

fn get_tag_len(provider: Provider, cipher: Cipher) -> usize {
    match provider {
        Provider::Ring => get_ring_algorithm(cipher).tag_len(),
        Provider::RustCrypto => {
            todo!()
        }
    }
}

fn get_key_len(provider: Provider, cipher: Cipher) -> usize {
    match provider {
        Provider::Ring => get_ring_algorithm(cipher).key_len(),
        Provider::RustCrypto => {
            todo!()
        }
    }
}

/// Slit plaintext__and_tag__and_nonce in (plaintext, tag, nonce)
fn split_plaintext_tag_nonce_mut<'a>(data: &'a mut [u8], plaintext_len: usize, tag_len: usize, nonce_len: usize) -> (&'a mut [u8], &'a mut [u8], &'a mut [u8]) {
    let (plaintext, tag_and_nonce_and_free) = data.split_at_mut(plaintext_len);
    let (tag, nonce_and_free) = tag_and_nonce_and_free.split_at_mut(tag_len);
    let (nonce, _) = nonce_and_free.split_at_mut(nonce_len);
    (plaintext, tag, nonce)
}

/// Slit plaintext__and_tag__and_nonce in (plaintext_and_tag, nonce)
fn split_plaintext_and_tag_nonce_mut<'a>(data: &'a mut [u8], plaintext_and_tag_and_nonce_len: usize, nonce_len: usize) -> (&'a mut [u8], &'a mut [u8]) {
    let (plaintext_and_tag, nonce_and_free) = data.split_at_mut(plaintext_and_tag_and_nonce_len - nonce_len);
    let (nonce, _) = nonce_and_free.split_at_mut(nonce_len);
    (plaintext_and_tag, nonce)
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

#[cfg(test)]
mod tests {
    use super::*;

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

        assert_eq!(src.len() % chunk_size, 0, "Array size must be a multiple of chunk size");

        dst.par_chunks_mut(chunk_size).zip(src.par_chunks(chunk_size)).for_each(|(dst_chunk, src_chunk)| {
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
    fn test_encrypt_decrypt() {
        let cipher = Cipher::AES256GCM;
        let mut key = vec![0; 32];
        create_rng().fill_bytes(&mut key);
        let provider = Provider::Ring;

        let (sealing_key, nonce_sequence) = create_sealing_key(provider, cipher, &key);
        let (opening_key, last_nonce) = create_opening_key(provider, cipher, &key);

        let message_len = 4096;
        let overhead = get_tag_len(provider, cipher) + get_nonce_len(provider, cipher);
        let mut buf = vec![0; message_len + overhead];
        let mut plaintext = vec![0; message_len];
        create_rng().fill_bytes(&mut plaintext);
        buf[..message_len].copy_from_slice(&plaintext);
        {
            let (plaintext, tag_out, nonce_out) = split_plaintext_tag_nonce_mut(&mut buf, message_len, get_tag_len(provider, cipher), get_nonce_len(provider, cipher));
            encrypt(plaintext, 0, b"", Arc::new(Mutex::new(sealing_key)), nonce_sequence, tag_out, nonce_out);
        }

        let (plaintext_and_tag, nonce_out) = split_plaintext_and_tag_nonce_mut(&mut buf, message_len + overhead, get_nonce_len(provider, cipher));
        let plaintext2 = decrypt(plaintext_and_tag, 0, b"", Arc::new(Mutex::new(opening_key)), last_nonce, &nonce_out);

        assert_eq!(plaintext, plaintext2);
    }
}
