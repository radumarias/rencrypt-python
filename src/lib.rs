#![deny(warnings)]
use ::secrets::SecretVec;
use numpy::{PyArray1, PyArrayMethods};
use std::sync::{Arc, Mutex};

use crate::CipherMeta::Ring;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use rayon::iter::IndexedParallelIterator;
use rayon::iter::ParallelIterator;
use rayon::prelude::{ParallelSlice, ParallelSliceMut};
use ring::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM,
    CHACHA20_POLY1305,
};
use ring::error::Unspecified;
use zeroize::Zeroize;

mod cipher;
mod secrets;

// 256KB seems to be the optimal block size that offers the max MB/s speed for encryption,
// on benchmarks that seem to be the case.
// We performed 10.000 encryption operations for each size varying from 64KB to 1GB,
// after 8MB it tops up to similar values.
// Const FILE_BLOCK_LEN: usize = 256 * 1024;

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

    /// Max length (in bytes) of the plaintext that can be encrypted before becoming unsafe.
    #[must_use]
    #[allow(clippy::use_self)]
    #[pyo3(signature = ())]
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
        let mut rng = create_rng();
        unsafe {
            rng.fill_bytes(key.as_bytes_mut());
        }
    }
}

#[pyclass]
pub struct Cipher {
    cipher_meta: CipherMeta,
    sealing_key: Arc<Mutex<SealingKey<RandomNonceSequenceWrapper>>>,
    nonce_sequence: Arc<Mutex<RandomNonceSequence>>,
    last_nonce: Arc<Mutex<Vec<u8>>>,
    opening_key: Arc<Mutex<OpeningKey<ExistingNonceSequence>>>,
    // key: SecretVec<u8>,
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

        let alg = match cipher_meta {
            Ring { alg } => alg,
        };
        let (sealing_key, nonce_sequence) = create_ring_sealing_key(alg, &key);
        let (opening_key, last_nonce) = create_ring_opening_key(alg, &key);

        Ok(Self {
            cipher_meta,
            sealing_key: Arc::new(Mutex::new(sealing_key)),
            nonce_sequence,
            last_nonce,
            opening_key: Arc::new(Mutex::new(opening_key)),
            // key,
        })
    }

    pub fn ciphertext_len(&self, plaintext_len: usize) -> usize {
        plaintext_len + overhead(self.cipher_meta)
    }

    pub fn encrypt(
        &self,
        buf: &Bound<'_, PyAny>,
        plaintext_len: usize,
        block_index: u64,
        aad: &[u8],
    ) -> PyResult<usize> {
        let (plaintext, tag_out, nonce_out) = split_plaintext_tag_nonce_mut(
            as_array_mut(buf)?,
            plaintext_len,
            tag_len(self.cipher_meta),
            nonce_len(self.cipher_meta),
        );
        encrypt(
            plaintext,
            block_index,
            aad,
            self.sealing_key.clone(),
            self.nonce_sequence.clone(),
            tag_out,
            nonce_out,
        );
        Ok(plaintext_len + overhead(self.cipher_meta))
    }

    pub fn encrypt_from<'py>(
        &self,
        plaintext: &Bound<'py, PyAny>,
        buf: &Bound<'py, PyAny>,
        block_index: u64,
        aad: &[u8],
    ) -> PyResult<usize> {
        let plaintext = as_array(plaintext)?;
        let buf = as_array_mut(buf)?;
        copy_slice(plaintext, buf);
        let (plaintext, tag_out, nonce_out) = split_plaintext_tag_nonce_mut(
            buf,
            plaintext.len(),
            tag_len(self.cipher_meta),
            nonce_len(self.cipher_meta),
        );
        encrypt(
            plaintext,
            block_index,
            aad,
            self.sealing_key.clone(),
            self.nonce_sequence.clone(),
            tag_out,
            nonce_out,
        );
        Ok(plaintext.len() + overhead(self.cipher_meta))
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
    //         let tag_len = tag_len(self.cipher_meta);
    //         let nonce_len = nonce_len(self.cipher_meta);
    //         let mut block_index = 0_u64;
    //         let overhead = overhead(self.cipher_meta);
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
    //     let tag_len = tag_len(self.cipher_meta);
    //     let nonce_len = nonce_len(self.cipher_meta);
    //     let provider = self.provider;
    //     let cipher = self.cipher;
    //     let key = &self.key;
    //
    //     let overhead = overhead(self.cipher_meta);
    //     let block_len = FILE_BLOCK_LEN;
    //
    //     let fin = File::open(src).unwrap();
    //     let file_size = fin.metadata().unwrap().len();
    //
    //     {
    //         // create out file with preallocated size
    //         let fout = File::create(dst).unwrap();
    //         fout.set_len(file_size + (file_size / block_len as u64 + 1) * overhead(self.cipher_meta) as u64).unwrap();
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

    pub fn decrypt(
        &mut self,
        buf: &Bound<'_, PyAny>,
        plaintext_and_tag_len: usize,
        block_index: u64,
        aad: &[u8],
    ) -> PyResult<usize> {
        let buf = as_array_mut(buf)?;
        let (ciphertext_and_tag, nonce) = split_plaintext_and_tag_nonce_mut(
            buf,
            plaintext_and_tag_len,
            nonce_len(self.cipher_meta),
        );
        decrypt(
            ciphertext_and_tag,
            block_index,
            aad,
            self.opening_key.clone(),
            self.last_nonce.clone(),
            nonce,
        );
        Ok(plaintext_and_tag_len - overhead(self.cipher_meta))
    }

    pub fn decrypt_from<'py>(
        &self,
        ciphertext_and_tag_and_nonce: &Bound<'py, PyAny>,
        buf: &Bound<'py, PyAny>,
        block_index: u64,
        aad: &[u8],
    ) -> PyResult<usize> {
        let ciphertext_and_tag_and_nonce = as_array(ciphertext_and_tag_and_nonce)?;
        let buf = as_array_mut(buf)?;
        copy_slice(ciphertext_and_tag_and_nonce, buf);
        let (ciphertext_and_tag, nonce) = split_plaintext_and_tag_nonce_mut(
            buf,
            ciphertext_and_tag_and_nonce.len(),
            nonce_len(self.cipher_meta),
        );
        let plaintext = decrypt(
            ciphertext_and_tag,
            block_index,
            aad,
            self.opening_key.clone(),
            self.last_nonce.clone(),
            nonce,
        );
        Ok(plaintext.len())
    }

    // pub fn decrypt_file(&mut self, src: &str, dst: &str, aad: &[u8]) -> PyResult<()> {
    //     let nonce_len = nonce_len(self.cipher_meta);
    //     let provider = self.provider;
    //     let cipher = self.cipher;
    //     let key = &self.key;
    //
    //     let overhead = overhead(self.cipher_meta);
    //     let block_len = FILE_BLOCK_LEN + overhead;
    //
    //     let fin = File::open(src).unwrap();
    //     let ciphertext_file_size = fin.metadata().unwrap().len();
    //     let plaintext_file_size = ciphertext_file_size - (ciphertext_file_size / block_len as u64 + 1) * overhead(self.cipher_meta) as u64;
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
    dst.copy_from_slice(src);
}

fn copy_slice_concurrently(dst: &mut [u8], src: &[u8], chunk_size: usize) {
    dst.par_chunks_mut(chunk_size)
        .zip(src.par_chunks(chunk_size))
        .for_each(|(dst_chunk, src_chunk)| {
            dst_chunk.copy_from_slice(src_chunk);
        });
}

fn get_ring_algorithm(alg: RingAlgorithm) -> &'static ring::aead::Algorithm {
    match alg {
        RingAlgorithm::ChaCha20Poly1305 => &CHACHA20_POLY1305,
        RingAlgorithm::AES256GCM => &AES_256_GCM,
    }
}

fn encrypt(
    plaintext: &mut [u8],
    block_index: u64,
    aad: &[u8],
    sealing_key: Arc<Mutex<SealingKey<RandomNonceSequenceWrapper>>>,
    nonce_sequence: Arc<Mutex<RandomNonceSequence>>,
    tag_out: &mut [u8],
    nonce_out: &mut [u8],
) {
    // lock here to keep the lock while encrypting
    let mut sealing_key = sealing_key.lock().unwrap();

    let block_index_bytes = block_index.to_le_bytes();
    let mut aad2 = vec![0; aad.len() + 8];
    aad2[..aad.len()].copy_from_slice(aad);
    aad2[aad.len()..].copy_from_slice(&block_index_bytes);
    let aad = Aad::<&[u8]>::from(aad2.as_ref());

    let tag = sealing_key
        .seal_in_place_separate_tag(aad, plaintext)
        .unwrap();

    tag_out.copy_from_slice(tag.as_ref());
    nonce_out.copy_from_slice(&nonce_sequence.lock().unwrap().last_nonce);
}

fn decrypt<'a>(
    ciphertext_and_tag: &'a mut [u8],
    block_index: u64,
    aad: &[u8],
    opening_key: Arc<Mutex<OpeningKey<ExistingNonceSequence>>>,
    last_nonce: Arc<Mutex<Vec<u8>>>,
    nonce: &[u8],
) -> &'a mut [u8] {
    // lock here to keep the lock while decrypting
    let mut opening_key = opening_key.lock().unwrap();

    last_nonce.lock().unwrap().copy_from_slice(nonce);

    let block_index_bytes = block_index.to_le_bytes();
    let mut aad2 = vec![0; aad.len() + 8];
    aad2[..aad.len()].copy_from_slice(aad);
    aad2[aad.len()..].copy_from_slice(&block_index_bytes);
    let aad = Aad::<&[u8]>::from(aad2.as_ref());

    let plaintext = opening_key
        .open_within(aad, ciphertext_and_tag, 0..)
        .unwrap();
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

fn create_ring_sealing_key(
    alg: RingAlgorithm,
    key: &SecretVec<u8>,
) -> (
    SealingKey<RandomNonceSequenceWrapper>,
    Arc<Mutex<RandomNonceSequence>>,
) {
    // Create a new NonceSequence type which generates nonces
    let nonce_seq = Arc::new(Mutex::new(RandomNonceSequence::new(
        get_ring_algorithm(alg).nonce_len(),
    )));
    let nonce_sequence = nonce_seq.clone();
    let nonce_wrapper = RandomNonceSequenceWrapper::new(nonce_seq.clone());
    // Create a new AEAD key without a designated role or nonce sequence
    let unbound_key = UnboundKey::new(get_ring_algorithm(alg), &key.borrow()).unwrap();

    // Create a new AEAD key for encrypting and signing ("sealing"), bound to a nonce sequence
    // The SealingKey can be used multiple times, each time a new nonce will be used
    let sealing_key = SealingKey::new(unbound_key, nonce_wrapper);
    (sealing_key, nonce_sequence)
}

fn create_ring_opening_key(
    alg: RingAlgorithm,
    key: &SecretVec<u8>,
) -> (OpeningKey<ExistingNonceSequence>, Arc<Mutex<Vec<u8>>>) {
    let last_nonce = Arc::new(Mutex::new(vec![0_u8; get_ring_algorithm(alg).nonce_len()]));
    let unbound_key = UnboundKey::new(get_ring_algorithm(alg), &key.borrow()).unwrap();
    let nonce_sequence = ExistingNonceSequence::new(last_nonce.clone());
    let opening_key = OpeningKey::new(unbound_key, nonce_sequence);
    (opening_key, last_nonce)
}

pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn nonce_len(cipher_meta: CipherMeta) -> usize {
    match cipher_meta {
        Ring { alg } => get_ring_algorithm(alg).nonce_len(),
        // RustCrypto { alg } => (alg).nonce_len(),
    }
}

fn tag_len(cipher_meta: CipherMeta) -> usize {
    match cipher_meta {
        Ring { alg } => get_ring_algorithm(alg).tag_len(),
        // RustCrypto { alg } => (alg).tag_len(),
    }
}

fn key_len(cipher_meta: CipherMeta) -> usize {
    match cipher_meta {
        Ring { alg } => get_ring_algorithm(alg).key_len(),
        // RustCrypto { alg } => (alg).key_len(),
    }
}

pub fn overhead(cipher_meta: CipherMeta) -> usize {
    tag_len(cipher_meta) + nonce_len(cipher_meta)
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
    fn test_encrypt_decrypt() {
        let cipher_meta = Ring {
            alg: RingAlgorithm::AES256GCM,
        };
        let alg = match cipher_meta {
            Ring { alg } => alg,
        };
        let key = SecretVec::new(get_ring_algorithm(alg).key_len(), |s| {
            create_rng().fill_bytes(s);
        });
        let (sealing_key, nonce_sequence) = create_ring_sealing_key(alg, &key);
        let (opening_key, last_nonce) = create_ring_opening_key(alg, &key);

        let message_len = 4096;
        let overhead = tag_len(cipher_meta) + nonce_len(cipher_meta);
        let mut buf = vec![0; message_len + overhead];
        let mut plaintext = vec![0; message_len];
        create_rng().fill_bytes(&mut plaintext);
        buf[..message_len].copy_from_slice(&plaintext);
        {
            let (plaintext, tag_out, nonce_out) = split_plaintext_tag_nonce_mut(
                &mut buf,
                message_len,
                tag_len(cipher_meta),
                nonce_len(cipher_meta),
            );
            encrypt(
                plaintext,
                0,
                b"",
                Arc::new(Mutex::new(sealing_key)),
                nonce_sequence,
                tag_out,
                nonce_out,
            );
        }

        let (plaintext_and_tag, nonce_out) = split_plaintext_and_tag_nonce_mut(
            &mut buf,
            message_len + overhead,
            nonce_len(cipher_meta),
        );
        let plaintext2 = decrypt(
            plaintext_and_tag,
            0,
            b"",
            Arc::new(Mutex::new(opening_key)),
            last_nonce,
            &nonce_out,
        );

        assert_eq!(plaintext, plaintext2);
    }
}
