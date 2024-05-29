use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use rayon::iter::IndexedParallelIterator;
use rayon::iter::ParallelIterator;
use rayon::prelude::{IntoParallelRefIterator, ParallelSlice, ParallelSliceMut};
use ring::aead::{Aad, AES_256_GCM, BoundKey, CHACHA20_POLY1305, Nonce, NONCE_LEN, NonceSequence, OpeningKey, SealingKey, UnboundKey};
use ring::error::Unspecified;
use zeroize::Zeroize;

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
    Aes256Gcm,
}

#[pymethods]
impl Cipher {
    /// In bytes.
    #[must_use]
    #[allow(clippy::use_self)]
    #[pyo3(signature = ())]
    pub fn key_len(&self) -> usize {
        match self {
            Cipher::ChaCha20Poly1305 => CHACHA20_POLY1305.key_len(),
            Cipher::Aes256Gcm => AES_256_GCM.key_len(),
        }
    }

    /// Max length (in bytes) of the plaintext that can be encrypted before becoming unsafe.
    #[must_use]
    #[allow(clippy::use_self)]
    #[pyo3(signature = ())]
    pub const fn max_plaintext_len(&self) -> usize {
        match self {
            Cipher::ChaCha20Poly1305 => (2_usize.pow(32) - 1) * 64,
            Cipher::Aes256Gcm => (2_usize.pow(39) - 256) / 8,
        }
    }

    pub fn generate_key<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let mut rng = create_rng();
        let mut key = vec![0; self.key_len()];
        rng.fill_bytes(&mut key);
        Ok(PyBytes::new_bound(py, key.as_slice()))
    }
}

#[pyclass]
pub struct REncrypt {
    provider: Provider,
    cipher: Cipher,
    sealing_key: Arc<Mutex<SealingKey<RandomNonceSequenceWrapper>>>,
    nonce_sequence: Arc<Mutex<RandomNonceSequence>>,
    last_nonce: Arc<Mutex<Option<Vec<u8>>>>,
    opening_key: Arc<Mutex<OpeningKey<ExistingNonceSequence>>>,
    key: Vec<u8>,
}

const FILE_BLOCK_LEN: usize = 128 * 1024;

#[pymethods]
impl REncrypt {
    #[new]
    pub fn new(cipher: Cipher, key: &[u8]) -> Self {
        let key = key.to_vec();

        let (sealing_key, nonce_sequence) = create_sealing_key(cipher, &key);
        let (opening_key, last_nonce) = create_opening_key(cipher, &key);

        Self {
            provider: Provider::Ring,
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

    // #[pyo3(signature = (buf = [42], len = 42, aad = &[42]))]
    pub fn encrypt_buf<'py>(&self, buf: &Bound<'py, PyByteArray>, len: usize, block_index: u64, aad: &[u8]) -> PyResult<usize> {
        let data = unsafe { buf.as_bytes_mut() };
        let tag_len = self.get_tag_len();
        let nonce_len = self.get_nonce_len();
        encrypt(&mut data[..len + self.overhead()], len, block_index, aad, self.sealing_key.clone(), self.nonce_sequence.clone(), tag_len, nonce_len);
        Ok(len + self.overhead())
    }

    pub fn encrypt_to_buf<'py>(&self, plaintext: &[u8], buf: &Bound<'py, PyByteArray>, block_index: u64, aad: &[u8]) -> PyResult<usize> {
        let data = unsafe { buf.as_bytes_mut() };
        copy_slice(plaintext, data);
        let tag_len = self.get_tag_len();
        let nonce_len = self.get_nonce_len();
        encrypt(&mut data[..plaintext.len() + self.overhead()], plaintext.len(), block_index, aad, self.sealing_key.clone(), self.nonce_sequence.clone(), tag_len, nonce_len);
        Ok(plaintext.len() + self.overhead())
    }

    pub fn encrypt_from<'py>(&mut self, plaintext: &[u8], block_index: u64, aad: &[u8], py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let mut buf = vec![0; plaintext.len() + self.overhead()];
        copy_slice(plaintext, &mut buf);
        let tag_len = self.get_tag_len();
        let nonce_len = self.get_nonce_len();
        encrypt(&mut buf, plaintext.len(), block_index, aad, self.sealing_key.clone(), self.nonce_sequence.clone(), tag_len, nonce_len);
        Ok(PyBytes::new_bound(py, buf.as_slice()))
    }

    pub fn encrypt_file(&mut self, src: &str, dst: &str, aad: &[u8]) -> PyResult<()> {
        let tag_len = self.get_tag_len();
        let nonce_len = self.get_nonce_len();
        let cipher = self.cipher;
        let key = &self.key;

        let overhead = self.overhead();
        let block_len = FILE_BLOCK_LEN;

        let fin = File::open(src).unwrap();
        let file_size = fin.metadata().unwrap().len();

        {
            // create out file with preallocated size
            let fout = File::create(dst).unwrap();
            fout.set_len(file_size + (file_size / block_len as u64 + 1) * self.overhead() as u64).unwrap();
            fout.sync_all().unwrap();
            File::open(Path::new(dst).to_path_buf().parent().expect("oops, we don't have parent")).unwrap().sync_all().unwrap();
        }

        let chunks: Vec<(u64, usize)> = (0..file_size)
            .step_by(block_len)
            .map(|offset| {
                let end = std::cmp::min(offset + block_len as u64, file_size);
                (offset, (end - offset) as usize)
            })
            .collect();
        chunks.par_iter().for_each(|&(offset, length)| {
            // read
            let mut buffer = vec![0u8; length + overhead];
            let mut src_file = BufReader::new(File::open(src).expect("Unable to open source file"));
            src_file.seek(SeekFrom::Start(offset)).expect("Unable to seek in source file");
            src_file.read_exact(&mut buffer[..length]).expect("Unable to read chunk from source file");

            // encrypt
            let (sealing_key, nonce_sequence) = create_sealing_key(cipher, &key);
            let block_index = offset / block_len as u64;
            encrypt(&mut buffer, length, block_index, &aad, Arc::new(Mutex::new(sealing_key)), nonce_sequence.clone(), tag_len, nonce_len);

            // write
            let mut dst_file = BufWriter::new(OpenOptions::new().write(true).open(dst).expect("Unable to open destination file"));
            dst_file.seek(SeekFrom::Start(offset + block_index * overhead as u64)).expect("Unable to seek in destination file");
            dst_file.write_all(&buffer).expect("Unable to write chunk to destination file");
            dst_file.flush().expect("Unable to flush destination file");

            buffer.zeroize();
        });

        let fout = File::open(dst).unwrap();
        fout.sync_data().unwrap();
        File::open(Path::new(dst).to_path_buf().parent().expect("oops, we don't have parent")).unwrap().sync_all().unwrap();

        Ok(())
    }

    pub fn decrypt_buf<'py>(&mut self, buf: &Bound<'py, PyByteArray>, len: usize, block_index: u64, aad: &[u8]) -> PyResult<usize> {
        let data = unsafe { buf.as_bytes_mut() };
        let nonce_len = self.get_nonce_len();
        decrypt(&mut data[..len], block_index, aad, self.opening_key.clone(), self.last_nonce.clone(), nonce_len);
        Ok(len - self.overhead())
    }

    pub fn decrypt_to_buf<'py>(&self, ciphertext: &[u8], buf: &Bound<'py, PyByteArray>, block_index: u64, aad: &[u8]) -> PyResult<usize> {
        let data = unsafe { buf.as_bytes_mut() };
        copy_slice(ciphertext, data);
        let nonce_len = self.get_nonce_len();
        decrypt(&mut data[..ciphertext.len()], block_index, aad, self.opening_key.clone(), self.last_nonce.clone(), nonce_len);
        Ok(ciphertext.len() - self.overhead())
    }

    pub fn decrypt_from<'py>(&self, py: Python<'py>, ciphertext: &[u8], block_index: u64, aad: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let mut data = vec![0_u8; ciphertext.len()];
        copy_slice(ciphertext, &mut data);
        let nonce_len = self.get_nonce_len();
        decrypt(&mut data, block_index, aad, self.opening_key.clone(), self.last_nonce.clone(), nonce_len);
        Ok(PyBytes::new_bound(py, &data[..ciphertext.len() - self.overhead()]))
    }

    pub fn decrypt_file(&mut self, src: &str, dst: &str, aad: &[u8]) -> PyResult<()> {
        let nonce_len = self.get_nonce_len();
        let cipher = self.cipher;
        let key = &self.key;

        let overhead = self.overhead();
        let block_len = FILE_BLOCK_LEN + overhead;

        let fin = File::open(src).unwrap();
        let ciphertext_file_size = fin.metadata().unwrap().len();
        let plaintext_file_size = ciphertext_file_size - (ciphertext_file_size / block_len as u64 + 1) * self.overhead() as u64;

        {
            // create out file with preallocated size
            let fout = File::create(dst).unwrap();
            fout.set_len(plaintext_file_size).unwrap();
            fout.sync_all().unwrap();
            File::open(Path::new(dst).to_path_buf().parent().expect("oops, we don't have parent")).unwrap().sync_all().unwrap();
        }

        let chunks: Vec<(u64, usize)> = (0..ciphertext_file_size)
            .step_by(block_len)
            .map(|offset| {
                let end = std::cmp::min(offset + block_len as u64, ciphertext_file_size);
                (offset, (end - offset) as usize)
            })
            .collect();
        chunks.par_iter().for_each(|&(offset, length)| {
            // read
            let mut buffer = vec![0u8; length];
            let mut src_file = BufReader::new(File::open(src).expect("Unable to open source file"));
            src_file.seek(SeekFrom::Start(offset)).expect("Unable to seek in source file");
            src_file.read_exact(&mut buffer).expect("Unable to read chunk from source file");

            // decrypt
            let (opening_key, last_nonce) = create_opening_key(cipher, &key);
            let block_index = offset / block_len as u64;
            decrypt(&mut buffer, block_index, &aad, Arc::new(Mutex::new(opening_key)), last_nonce.clone(), nonce_len);

            // write
            let mut dst_file = BufWriter::new(OpenOptions::new().write(true).open(dst).expect("Unable to open destination file"));
            dst_file.seek(SeekFrom::Start(offset - block_index * overhead as u64)).expect("Unable to seek in destination file");
            dst_file.write_all(&buffer[..length - overhead]).expect("Unable to write chunk to destination file");
            dst_file.flush().expect("Unable to flush destination file");

            buffer.zeroize();
        });

        let fout = File::open(dst).unwrap();
        fout.sync_data().unwrap();
        File::open(Path::new(dst).to_path_buf().parent().expect("oops, we don't have parent")).unwrap().sync_all().unwrap();

        Ok(())
    }

    #[staticmethod]
    pub fn copy_slice<'py>(src: &[u8], buf: &Bound<'py, PyByteArray>) -> PyResult<()> {
        let data = unsafe { buf.as_bytes_mut() };
        copy_slice(src, data);
        Ok(())
    }

    fn get_nonce_len(&self) -> usize {
        match self.provider {
            Provider::Ring => get_ring_algorithm(self.cipher).nonce_len(),
            Provider::RustCrypto => {
                todo!()
            }
        }
    }

    fn get_tag_len(&self) -> usize {
        match self.provider {
            Provider::Ring => get_ring_algorithm(self.cipher).tag_len(),
            Provider::RustCrypto => {
                todo!()
            }
        }
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
    last_nonce: Option<Vec<u8>>,
}

impl Default for RandomNonceSequence {
    fn default() -> Self {
        Self {
            rng: Box::new(create_rng()),
            last_nonce: None,
        }
    }
}

impl NonceSequence for RandomNonceSequence {
    // called once for each seal operation
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.last_nonce = Some(vec![0; NONCE_LEN]);
        self.rng.fill_bytes(self.last_nonce.as_mut().unwrap());
        Nonce::try_assume_unique_for_key(self.last_nonce.as_mut().unwrap())
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
        Cipher::Aes256Gcm => &AES_256_GCM,
    }
}

fn encrypt(buf: &mut [u8], len: usize, block_index: u64, aad: &[u8],
           sealing_key: Arc<Mutex<SealingKey<RandomNonceSequenceWrapper>>>, nonce_sequence: Arc<Mutex<RandomNonceSequence>>,
           tag_len: usize, nonce_len: usize) {
    // lock here to keep the lock while encrypting
    let mut sealing_key = sealing_key.lock().unwrap();

    let block_index_bytes = block_index.to_le_bytes();
    let mut aad2 = vec![0; aad.len() + 8];
    aad2[..aad.len()].copy_from_slice(aad);
    aad2[aad.len()..].copy_from_slice(&block_index_bytes);
    let aad = Aad::<&[u8]>::from(aad2.as_ref());

    let tag = sealing_key.seal_in_place_separate_tag(aad, &mut buf[..len]).unwrap();

    let tag_start = len;
    buf[tag_start..tag_start + tag_len].copy_from_slice(tag.as_ref());

    let nonce_start = tag_start + tag_len;
    buf[nonce_start..nonce_start + nonce_len].copy_from_slice(nonce_sequence.lock().unwrap().last_nonce.as_ref().unwrap().as_ref());
}

fn decrypt<'a>(buf: &'a mut [u8], block_index: u64, aad: &[u8], opening_key: Arc<Mutex<OpeningKey<ExistingNonceSequence>>>,
               last_nonce: Arc<Mutex<Option<Vec<u8>>>>, nonce_len: usize) -> &'a mut [u8] {
    // lock here to keep the lock while decrypting
    let mut opening_key = opening_key.lock().unwrap();

    let len = buf.len();
    last_nonce.lock().unwrap().replace(buf[len - nonce_len..len].to_vec());

    let block_index_bytes = block_index.to_le_bytes();
    let mut aad2 = vec![0; aad.len() + 8];
    aad2[..aad.len()].copy_from_slice(aad);
    aad2[aad.len()..].copy_from_slice(&block_index_bytes);
    let aad = Aad::<&[u8]>::from(aad2.as_ref());

    let plaintext = opening_key.open_within(aad, &mut buf[..len - nonce_len], 0..).unwrap();
    plaintext
}

fn copy_slice(src: &[u8], buf: &mut [u8]) {
    if src.len() < 1024 * 1024 {
        let src_len = src.len();
        copy_slice_internal(&mut buf[..src_len], src);
    } else {
        copy_slice_concurrently(&mut buf[..src.len()], src, 16 * 1024);
    }
}

fn create_sealing_key(cipher: Cipher, key: &Vec<u8>) -> (SealingKey<RandomNonceSequenceWrapper>, Arc<Mutex<RandomNonceSequence>>) {
    // Create a new NonceSequence type which generates nonces
    let nonce_seq = Arc::new(Mutex::new(RandomNonceSequence::default()));
    let nonce_sequence = nonce_seq.clone();
    let nonce_wrapper = RandomNonceSequenceWrapper::new(nonce_seq.clone());
    // Create a new AEAD key without a designated role or nonce sequence
    let unbound_key = UnboundKey::new(get_ring_algorithm(cipher), key).unwrap();

    // Create a new AEAD key for encrypting and signing ("sealing"), bound to a nonce sequence
    // The SealingKey can be used multiple times, each time a new nonce will be used
    let sealing_key = SealingKey::new(unbound_key, nonce_wrapper);
    (sealing_key, nonce_sequence)
}

fn create_opening_key(cipher: Cipher, key: &Vec<u8>) -> (OpeningKey<ExistingNonceSequence>, Arc<Mutex<Option<Vec<u8>>>>) {
    let last_nonce = Arc::new(Mutex::new(None));
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


pub(crate) struct ExistingNonceSequence {
    last_nonce: Arc<Mutex<Option<Vec<u8>>>>,
}

impl ExistingNonceSequence {
    pub fn new(last_nonce: Arc<Mutex<Option<Vec<u8>>>>) -> Self {
        Self { last_nonce }
    }
}

impl NonceSequence for ExistingNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        Nonce::try_assume_unique_for_key(self.last_nonce.lock().unwrap().as_mut().unwrap())
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
}
