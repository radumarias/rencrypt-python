import pytest
import errno
import hashlib
import io
from pathlib import Path
import shutil
from rencrypt import Cipher, CipherMeta, RingAlgorithm, RustCryptoAlgorithm, SodiumoxideAlgorithm, OrionAlgorithm
import os
import unittest
import numpy as np
from zeroize import zeroize1, mlock, munlock
import platform


def setup_memory_limit():
    if not platform.system() == "Windows":
        return

    import ctypes
    from ctypes import wintypes

    # Define the Windows API functions
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    GetCurrentProcess = kernel32.GetCurrentProcess
    GetCurrentProcess.restype = wintypes.HANDLE

    SetProcessWorkingSetSize = kernel32.SetProcessWorkingSetSize
    SetProcessWorkingSetSize.restype = wintypes.BOOL
    SetProcessWorkingSetSize.argtypes = [wintypes.HANDLE, ctypes.c_size_t, ctypes.c_size_t]

    # Get the handle of the current process
    current_process = GetCurrentProcess()

    # Set the working set size
    min_size = 6 * 1024 * 1024  # Minimum working set size
    max_size = 10 * 1024 * 1024  # Maximum working set size

    result = SetProcessWorkingSetSize(current_process, min_size, max_size)

    if not result:
        error_code = ctypes.get_last_error()
        error_message = ctypes.FormatError(error_code)
        raise RuntimeError(f"SetProcessWorkingSetSize failed with error code {error_code}: {error_message}")


def read_file_in_chunks(file_path, buf):
    with open(file_path, "rb") as file:
        buffered_reader = io.BufferedReader(file, buffer_size=len(buf))
        while True:
            read = buffered_reader.readinto(buf)
            if read == 0:
                break
            yield read


def calculate_file_hash(file_path):
    hash_algo = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_algo.update(chunk)
    return hash_algo.hexdigest()


def compare_files_by_hash(file1, file2):
    return calculate_file_hash(file1) == calculate_file_hash(file2)


def silentremove(filename):
    try:
        os.remove(filename)
    except OSError as e:  # this would be "except OSError, e:" before Python 2.6
        if e.errno != errno.ENOENT:  # errno.ENOENT = no such file or directory
            raise  # re-raise exception if a different error occurred


def create_directory_in_home(dir_name):
    # Get the user's home directory
    home_dir = Path.home()

    # Create the full path for the new directory
    new_dir_path = home_dir / dir_name

    # Create the directory
    try:
        new_dir_path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"Error creating directory: {e}")

    return new_dir_path.absolute().__str__()


def create_file_with_size(file_path_str, size_in_bytes):
    with open(file_path_str, "wb") as f:
        for _ in range(size_in_bytes // 4096):
            f.write(os.urandom(4096))


def delete_dir(path):
    if os.path.exists(path):
        shutil.rmtree(path)
    else:
        print(f"Directory {path} does not exist.")


def seal_and_open_in_place(this, cipher_meta):
    print(f"Testing {cipher_meta} {cipher_meta.alg}")
    
    key_len = cipher_meta.key_len()
    key = bytearray(key_len)
    mlock(key)
    cipher_meta.generate_key(key)
    munlock(key)
    cipher = Cipher(cipher_meta, key)

    # we create a buffer based on plaintext block len of 4096
    # the actual buffer needs to be a bit larger as the ciphertext also includes the tag and nonce
    plaintext_len = 256 * 1024
    ciphertext_len = cipher_meta.ciphertext_len(plaintext_len)
    buf = np.array([0] * ciphertext_len, dtype=np.uint8)
    mlock(buf)

    # put some plaintext in the buffer, it would be ideal if you can directly collect the data into the buffer without allocating new memory
    # but for the sake of example we will allocate and copy the data
    plaintext = bytearray(os.urandom(plaintext_len))
    mlock(plaintext)
    aad = b"AAD"
    # cipher.copy_slice is slighlty faster than buf[:plaintext_len] = plaintext, especially for large plaintext, because it copies the data in parallel
    # cipher.copy_slice takes bytes as input, cipher.copy_slice takes bytearray
    cipher.copy_slice(plaintext, buf)
    # encrypt it, this will encrypt in-place the data in the buffer
    ciphertext_len = cipher.seal_in_place(buf, plaintext_len, 42, aad)
    buf[:ciphertext_len]

    # decrypt it
    # if you need to copy ciphertext to buffer, we don't need to do it now as it's already in the buffer
    # cipher.copy_slice(ciphertext, buf[:len(ciphertext)])
    plaintext_len = cipher.open_in_place(buf, ciphertext_len, 42, aad)
    plaintext2 = buf[:plaintext_len]
    this.assertEqual(plaintext, plaintext2)

    zeroize1(plaintext)
    zeroize1(buf)
    munlock(plaintext)
    munlock(buf)


def seal_and_open_in_place_nonce(this, cipher_meta):
    print(f"Testing {cipher_meta} {cipher_meta.alg}")
    
    key_len = cipher_meta.key_len()
    key = bytearray(key_len)
    mlock(key)
    cipher_meta.generate_key(key)
    munlock(key)
    cipher = Cipher(cipher_meta, key)

    # we create a buffer based on plaintext block len of 4096
    # the actual buffer needs to be a bit larger as the ciphertext also includes the tag and nonce
    plaintext_len = 256 * 1024
    ciphertext_len = cipher_meta.ciphertext_len(plaintext_len)
    buf = np.array([0] * ciphertext_len, dtype=np.uint8)
    mlock(buf)

    # put some plaintext in the buffer, it would be ideal if you can directly collect the data into the buffer without allocating new memory
    # but for the sake of example we will allocate and copy the data
    plaintext = bytearray(os.urandom(plaintext_len))
    mlock(plaintext)
    aad = b"AAD"
    nonce = os.urandom(cipher_meta.nonce_len())
    # cipher.copy_slice is slighlty faster than buf[:plaintext_len] = plaintext, especially for large plaintext, because it copies the data in parallel
    # cipher.copy_slice takes bytes as input, cipher.copy_slice takes bytearray
    cipher.copy_slice(plaintext, buf)
    # encrypt it, this will encrypt in-place the data in the buffer
    ciphertext_len = cipher.seal_in_place(buf, plaintext_len, 42, aad, nonce)
    buf[:ciphertext_len]

    # decrypt it
    # if you need to copy ciphertext to buffer, we don't need to do it now as it's already in the buffer
    # cipher.copy_slice(ciphertext, buf[:len(ciphertext)])
    plaintext_len = cipher.open_in_place(buf, ciphertext_len, 42, aad)
    plaintext2 = buf[:plaintext_len]
    this.assertEqual(plaintext, plaintext2)

    zeroize1(plaintext)
    zeroize1(buf)
    munlock(plaintext)
    munlock(buf)


def seal_and_open_in_place_no_block_index(this, cipher_meta):
    print(f"Testing {cipher_meta} {cipher_meta.alg}")
    
    key_len = cipher_meta.key_len()
    key = bytearray(key_len)
    mlock(key)
    cipher_meta.generate_key(key)
    munlock(key)
    cipher = Cipher(cipher_meta, key)

    # we create a buffer based on plaintext block len of 4096
    # the actual buffer needs to be a bit larger as the ciphertext also includes the tag and nonce
    plaintext_len = 256 * 1024
    ciphertext_len = cipher_meta.ciphertext_len(plaintext_len)
    buf = np.array([0] * ciphertext_len, dtype=np.uint8)
    mlock(buf)

    # put some plaintext in the buffer, it would be ideal if you can directly collect the data into the buffer without allocating new memory
    # but for the sake of example we will allocate and copy the data
    plaintext = bytearray(os.urandom(plaintext_len))
    mlock(plaintext)
    aad = b"AAD"

    # cipher.copy_slice is slighlty faster than buf[:plaintext_len] = plaintext, especially for large plaintext, because it copies the data in parallel
    # cipher.copy_slice takes bytes as input, cipher.copy_slice takes bytearray
    cipher.copy_slice(plaintext, buf)
    # encrypt it, this will encrypt in-place the data in the buffer
    ciphertext_len = cipher.seal_in_place(buf, plaintext_len, None, aad)
    buf[:ciphertext_len]

    # decrypt it
    # if you need to copy ciphertext to buffer, we don't need to do it now as it's already in the buffer
    # cipher.copy_slice(ciphertext, buf[:len(ciphertext)])
    plaintext_len = cipher.open_in_place(buf, ciphertext_len, None, aad)
    plaintext2 = buf[:plaintext_len]
    this.assertEqual(plaintext, plaintext2)

    zeroize1(plaintext)
    zeroize1(buf)
    munlock(plaintext)
    munlock(buf)

def seal_and_open_in_place_no_aad(this, cipher_meta):
    print(f"Testing {cipher_meta} {cipher_meta.alg}")
    
    key_len = cipher_meta.key_len()
    key = bytearray(key_len)
    mlock(key)
    cipher_meta.generate_key(key)
    munlock(key)
    cipher = Cipher(cipher_meta, key)

    # we create a buffer based on plaintext block len of 4096
    # the actual buffer needs to be a bit larger as the ciphertext also includes the tag and nonce
    plaintext_len = 256 * 1024
    ciphertext_len = cipher_meta.ciphertext_len(plaintext_len)
    buf = np.array([0] * ciphertext_len, dtype=np.uint8)
    mlock(buf)

    # put some plaintext in the buffer, it would be ideal if you can directly collect the data into the buffer without allocating new memory
    # but for the sake of example we will allocate and copy the data
    plaintext = bytearray(os.urandom(plaintext_len))
    mlock(plaintext)

    # cipher.copy_slice is slighlty faster than buf[:plaintext_len] = plaintext, especially for large plaintext, because it copies the data in parallel
    # cipher.copy_slice takes bytes as input, cipher.copy_slice takes bytearray
    cipher.copy_slice(plaintext, buf)
    # encrypt it, this will encrypt in-place the data in the buffer
    ciphertext_len = cipher.seal_in_place(buf, plaintext_len, 42)
    buf[:ciphertext_len]

    # decrypt it
    # if you need to copy ciphertext to buffer, we don't need to do it now as it's already in the buffer
    # cipher.copy_slice(ciphertext, buf[:len(ciphertext)])
    plaintext_len = cipher.open_in_place(buf, ciphertext_len, 42)
    plaintext2 = buf[:plaintext_len]
    this.assertEqual(plaintext, plaintext2)

    zeroize1(plaintext)
    zeroize1(buf)
    munlock(plaintext)
    munlock(buf)


def seal_and_open_in_place_from(this, cipher_meta):
    print(f"Testing {cipher_meta} {cipher_meta.alg}")
    
    key_len = cipher_meta.key_len()
    key = bytearray(key_len)
    mlock(key)
    cipher_meta.generate_key(key)
    munlock(key)
    cipher = Cipher(cipher_meta, key)

    # we create a buffer based on plaintext block len of 4096
    # the actual buffer needs to be a bit larger as the ciphertext also includes the tag and nonce
    plaintext_len = 256 * 1024
    ciphertext_len = cipher_meta.ciphertext_len(plaintext_len)
    buf = np.array([0] * ciphertext_len, dtype=np.uint8)
    mlock(buf)

    plaintext = bytearray(os.urandom(plaintext_len))
    mlock(plaintext)
    aad = b"AAD"

    # encrypt it, after this will have the ciphertext in the buffer
    ciphertext_len = cipher.seal_in_place_from(plaintext, buf, 42, aad)
    cipertext = bytes(buf[:ciphertext_len])

    # decrypt it
    plaintext_len = cipher.open_in_place_from(cipertext, buf, 42, aad)
    plaintext2 = buf[:plaintext_len]
    this.assertEqual(plaintext, plaintext2)

    zeroize1(plaintext)
    zeroize1(buf)
    munlock(plaintext)
    munlock(buf)


def seal_and_open_in_place_from_nonce(this, cipher_meta):
    print(f"Testing {cipher_meta} {cipher_meta.alg}")
    
    key_len = cipher_meta.key_len()
    key = bytearray(key_len)
    mlock(key)
    cipher_meta.generate_key(key)
    munlock(key)
    cipher = Cipher(cipher_meta, key)

    # we create a buffer based on plaintext block len of 4096
    # the actual buffer needs to be a bit larger as the ciphertext also includes the tag and nonce
    plaintext_len = 256 * 1024
    ciphertext_len = cipher_meta.ciphertext_len(plaintext_len)
    buf = np.array([0] * ciphertext_len, dtype=np.uint8)
    mlock(buf)

    plaintext = bytearray(os.urandom(plaintext_len))
    mlock(plaintext)
    aad = b"AAD"
    nonce = os.urandom(cipher_meta.nonce_len())

    # encrypt it, after this will have the ciphertext in the buffer
    ciphertext_len = cipher.seal_in_place_from(plaintext, buf, 42, aad, nonce)
    cipertext = bytes(buf[:ciphertext_len])

    # decrypt it
    plaintext_len = cipher.open_in_place_from(cipertext, buf, 42, aad)
    plaintext2 = buf[:plaintext_len]
    this.assertEqual(plaintext, plaintext2)

    zeroize1(plaintext)
    zeroize1(buf)
    munlock(plaintext)
    munlock(buf)


def seal_and_open_in_place_from_no_block_index(this, cipher_meta):
    print(f"Testing {cipher_meta} {cipher_meta.alg}")
    
    key_len = cipher_meta.key_len()
    key = bytearray(key_len)
    mlock(key)
    cipher_meta.generate_key(key)
    munlock(key)
    cipher = Cipher(cipher_meta, key)

    # we create a buffer based on plaintext block len of 4096
    # the actual buffer needs to be a bit larger as the ciphertext also includes the tag and nonce
    plaintext_len = 256 * 1024
    ciphertext_len = cipher_meta.ciphertext_len(plaintext_len)
    buf = np.array([0] * ciphertext_len, dtype=np.uint8)
    mlock(buf)

    plaintext = bytearray(os.urandom(plaintext_len))
    mlock(plaintext)
    aad = b"AAD"

    # encrypt it, after this will have the ciphertext in the buffer
    ciphertext_len = cipher.seal_in_place_from(plaintext, buf, None, aad)
    cipertext = bytes(buf[:ciphertext_len])

    # decrypt it
    plaintext_len = cipher.open_in_place_from(cipertext, buf, None, aad)
    plaintext2 = buf[:plaintext_len]
    this.assertEqual(plaintext, plaintext2)

    zeroize1(plaintext)
    zeroize1(buf)
    munlock(plaintext)
    munlock(buf)

def seal_and_open_in_place_from_no_aad(this, cipher_meta):
    print(f"Testing {cipher_meta} {cipher_meta.alg}")
    
    key_len = cipher_meta.key_len()
    key = bytearray(key_len)
    mlock(key)
    cipher_meta.generate_key(key)
    munlock(key)
    cipher = Cipher(cipher_meta, key)

    # we create a buffer based on plaintext block len of 4096
    # the actual buffer needs to be a bit larger as the ciphertext also includes the tag and nonce
    plaintext_len = 256 * 1024
    ciphertext_len = cipher_meta.ciphertext_len(plaintext_len)
    buf = np.array([0] * ciphertext_len, dtype=np.uint8)
    mlock(buf)

    plaintext = bytearray(os.urandom(plaintext_len))
    mlock(plaintext)

    # encrypt it, after this will have the ciphertext in the buffer
    ciphertext_len = cipher.seal_in_place_from(plaintext, buf, 42)
    cipertext = bytes(buf[:ciphertext_len])

    # decrypt it
    plaintext_len = cipher.open_in_place_from(cipertext, buf, 42)
    plaintext2 = buf[:plaintext_len]
    this.assertEqual(plaintext, plaintext2)

    zeroize1(plaintext)
    zeroize1(buf)
    munlock(plaintext)
    munlock(buf)


def seal_and_open_in_place_file(this, cipher_meta):
    print(f"Testing {cipher_meta} {cipher_meta.alg}")
    
    tmp_dir = create_directory_in_home("rencrypt_tmp")
    fin = tmp_dir + "/" + "fin"
    fout = tmp_dir + "/" + "fout.enc"
    create_file_with_size(fin, 10 * 1024 * 1024)

    chunk_len = 256 * 1024

    key_len = cipher_meta.key_len()
    key = bytearray(key_len)
    mlock(key)
    cipher_meta.generate_key(key)
    munlock(key)
    cipher = Cipher(cipher_meta, key)

    # we create a buffer based on plaintext block len of 4096
    # the actual buffer needs to be a bit larger as the ciphertext also includes the tag and nonce
    plaintext_len = chunk_len
    ciphertext_len = cipher_meta.ciphertext_len(plaintext_len)
    buf = np.array([0] * ciphertext_len, dtype=np.uint8)
    mlock(buf)

    # use some random per file in additional authenticated data to prevent blocks from being swapped between files
    aad = os.urandom(16)

    # encrypt
    with open(fout, "wb", buffering=plaintext_len) as file_out:
        i = 0
        for read in read_file_in_chunks(fin, buf[:plaintext_len]):
            ciphertext_len = cipher.seal_in_place(buf, read, i, aad)
            file_out.write(buf[:ciphertext_len])
            i += 1
        file_out.flush()

    # decrypt
    tmp = fout + ".dec"
    with open(tmp, "wb", buffering=plaintext_len) as file_out:
        i = 0
        for read in read_file_in_chunks(fout, buf):
            plaintext_len2 = cipher.open_in_place(buf, read, i, aad)
            file_out.write(buf[:plaintext_len2])
            i += 1
        file_out.flush()

    this.assertEqual(compare_files_by_hash(fin, tmp), True)
    
    delete_dir(tmp_dir)

    zeroize1(buf)
    munlock(buf)


class TestStringMethods(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setup_memory_limit()
    
    def test_encrypt(self):
        seal_and_open_in_place(self, CipherMeta.Ring(RingAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place(self, CipherMeta.Ring(RingAlgorithm.Aes128Gcm))
        seal_and_open_in_place(self, CipherMeta.Ring(RingAlgorithm.Aes256Gcm))

        seal_and_open_in_place(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.XChaCha20Poly1305))
        seal_and_open_in_place(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Gcm))
        seal_and_open_in_place(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Gcm))
        seal_and_open_in_place(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128GcmSiv))
        seal_and_open_in_place(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256GcmSiv))
        seal_and_open_in_place(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Siv))
        seal_and_open_in_place(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Siv))
        seal_and_open_in_place(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon128))
        seal_and_open_in_place(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon128a))
        seal_and_open_in_place(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon80pq))
        seal_and_open_in_place(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysI128))
        seal_and_open_in_place(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysI256))
        seal_and_open_in_place(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysII128))
        seal_and_open_in_place(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysII256))
        seal_and_open_in_place(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Eax))
        seal_and_open_in_place(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Eax))
            
        seal_and_open_in_place(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.ChaCha20Poly1305Ieft))
        seal_and_open_in_place(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.XChaCha20Poly1305Ieft))
        # seal_and_open_in_place(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.Aes256Gcm))
        
        seal_and_open_in_place(self, CipherMeta.Orion(OrionAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place(self, CipherMeta.Orion(OrionAlgorithm.XChaCha20Poly1305))
        

    def test_encrypt_nonce(self):
        seal_and_open_in_place_nonce(self, CipherMeta.Ring(RingAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_nonce(self, CipherMeta.Ring(RingAlgorithm.Aes128Gcm))
        seal_and_open_in_place_nonce(self, CipherMeta.Ring(RingAlgorithm.Aes256Gcm))

        seal_and_open_in_place_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.XChaCha20Poly1305))
        seal_and_open_in_place_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Gcm))
        seal_and_open_in_place_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Gcm))
        seal_and_open_in_place_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128GcmSiv))
        seal_and_open_in_place_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256GcmSiv))
        seal_and_open_in_place_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Siv))
        seal_and_open_in_place_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Siv))
        seal_and_open_in_place_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon128))
        seal_and_open_in_place_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon128a))
        seal_and_open_in_place_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon80pq))
        seal_and_open_in_place_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysI128))
        seal_and_open_in_place_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysI256))
        seal_and_open_in_place_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysII128))
        seal_and_open_in_place_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysII256))
        seal_and_open_in_place_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Eax))
        seal_and_open_in_place_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Eax))
            
        seal_and_open_in_place_nonce(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_nonce(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.ChaCha20Poly1305Ieft))
        seal_and_open_in_place_nonce(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.XChaCha20Poly1305Ieft))
        # seal_and_open_in_place_nonce(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.Aes256Gcm))

        seal_and_open_in_place_nonce(self, CipherMeta.Orion(OrionAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_nonce(self, CipherMeta.Orion(OrionAlgorithm.XChaCha20Poly1305))

    def seal_and_open_in_place_no_block_index(self):
        seal_and_open_in_place_no_block_index(self, CipherMeta.Ring(RingAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_no_block_index(self, CipherMeta.Ring(RingAlgorithm.Aes128Gcm))
        seal_and_open_in_place_no_block_index(self, CipherMeta.Ring(RingAlgorithm.Aes256Gcm))

        seal_and_open_in_place_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.XChaCha20Poly1305))
        seal_and_open_in_place_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Gcm))
        seal_and_open_in_place_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Gcm))
        seal_and_open_in_place_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128GcmSiv))
        seal_and_open_in_place_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256GcmSiv))
        seal_and_open_in_place_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Siv))
        seal_and_open_in_place_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Siv))
        seal_and_open_in_place_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon128))
        seal_and_open_in_place_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon128a))
        seal_and_open_in_place_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon80pq))
        seal_and_open_in_place_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysI128))
        seal_and_open_in_place_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysI256))
        seal_and_open_in_place_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysII128))
        seal_and_open_in_place_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysII256))
        seal_and_open_in_place_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Eax))
        seal_and_open_in_place_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Eax))
            
        seal_and_open_in_place_no_block_index(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_no_block_index(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.ChaCha20Poly1305Ieft))
        seal_and_open_in_place_no_block_index(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.XChaCha20Poly1305Ieft))
        # seal_and_open_in_place_no_block_index_and_aad(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.Aes256Gcm))

        seal_and_open_in_place_no_block_index(self, CipherMeta.Orion(OrionAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_no_block_index(self, CipherMeta.Orion(OrionAlgorithm.XChaCha20Poly1305))

    def seal_and_open_in_place_no_aad(self):
        seal_and_open_in_place_no_aad(self, CipherMeta.Ring(RingAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_no_aad(self, CipherMeta.Ring(RingAlgorithm.Aes128Gcm))
        seal_and_open_in_place_no_aad(self, CipherMeta.Ring(RingAlgorithm.Aes256Gcm))

        seal_and_open_in_place_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.XChaCha20Poly1305))
        seal_and_open_in_place_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Gcm))
        seal_and_open_in_place_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Gcm))
        seal_and_open_in_place_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128GcmSiv))
        seal_and_open_in_place_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256GcmSiv))
        seal_and_open_in_place_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Siv))
        seal_and_open_in_place_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Siv))
        seal_and_open_in_place_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon128))
        seal_and_open_in_place_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon128a))
        seal_and_open_in_place_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon80pq))
        seal_and_open_in_place_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysI128))
        seal_and_open_in_place_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysI256))
        seal_and_open_in_place_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysII128))
        seal_and_open_in_place_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysII256))
        seal_and_open_in_place_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Eax))
        seal_and_open_in_place_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Eax))
            
        seal_and_open_in_place_no_aad(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_no_aad(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.ChaCha20Poly1305Ieft))
        seal_and_open_in_place_no_aad(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.XChaCha20Poly1305Ieft))
        # seal_and_open_in_place_no_aad_and_aad(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.Aes256Gcm))

        seal_and_open_in_place_no_aad(self, CipherMeta.Orion(OrionAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_no_aad(self, CipherMeta.Orion(OrionAlgorithm.XChaCha20Poly1305))

    def test_encrypt_from(self):
        seal_and_open_in_place_from(self, CipherMeta.Ring(RingAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_from(self, CipherMeta.Ring(RingAlgorithm.Aes128Gcm))
        seal_and_open_in_place_from(self, CipherMeta.Ring(RingAlgorithm.Aes256Gcm))

        seal_and_open_in_place_from(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_from(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.XChaCha20Poly1305))
        seal_and_open_in_place_from(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Gcm))
        seal_and_open_in_place_from(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Gcm))
        seal_and_open_in_place_from(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128GcmSiv))
        seal_and_open_in_place_from(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256GcmSiv))
        seal_and_open_in_place_from(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Siv))
        seal_and_open_in_place_from(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Siv))
        seal_and_open_in_place_from(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon128))
        seal_and_open_in_place_from(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon128a))
        seal_and_open_in_place_from(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon80pq))
        seal_and_open_in_place_from(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysI128))
        seal_and_open_in_place_from(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysI256))
        seal_and_open_in_place_from(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysII128))
        seal_and_open_in_place_from(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysII256))
        seal_and_open_in_place_from(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Eax))
        seal_and_open_in_place_from(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Eax))
            
        seal_and_open_in_place_from(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_from(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.ChaCha20Poly1305Ieft))
        seal_and_open_in_place_from(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.XChaCha20Poly1305Ieft))
        # seal_and_open_in_place_from(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.Aes256Gcm))

        seal_and_open_in_place_from(self, CipherMeta.Orion(OrionAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_from(self, CipherMeta.Orion(OrionAlgorithm.XChaCha20Poly1305))

    def test_encrypt_from_nonce(self):
        seal_and_open_in_place_from_nonce(self, CipherMeta.Ring(RingAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_from_nonce(self, CipherMeta.Ring(RingAlgorithm.Aes128Gcm))
        seal_and_open_in_place_from_nonce(self, CipherMeta.Ring(RingAlgorithm.Aes256Gcm))

        seal_and_open_in_place_from_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_from_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.XChaCha20Poly1305))
        seal_and_open_in_place_from_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Gcm))
        seal_and_open_in_place_from_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Gcm))
        seal_and_open_in_place_from_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128GcmSiv))
        seal_and_open_in_place_from_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256GcmSiv))
        seal_and_open_in_place_from_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Siv))
        seal_and_open_in_place_from_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Siv))
        seal_and_open_in_place_from_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon128))
        seal_and_open_in_place_from_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon128a))
        seal_and_open_in_place_from_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon80pq))
        seal_and_open_in_place_from_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysI128))
        seal_and_open_in_place_from_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysI256))
        seal_and_open_in_place_from_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysII128))
        seal_and_open_in_place_from_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysII256))
        seal_and_open_in_place_from_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Eax))
        seal_and_open_in_place_from_nonce(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Eax))
            
        seal_and_open_in_place_from_nonce(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_from_nonce(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.ChaCha20Poly1305Ieft))
        seal_and_open_in_place_from_nonce(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.XChaCha20Poly1305Ieft))
        # seal_and_open_in_place_from_nonce(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.Aes256Gcm))

        seal_and_open_in_place_from_nonce(self, CipherMeta.Orion(OrionAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_from_nonce(self, CipherMeta.Orion(OrionAlgorithm.XChaCha20Poly1305))

    def seal_and_open_in_place_from_no_block_index(self):
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.Ring(RingAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.Ring(RingAlgorithm.Aes128Gcm))
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.Ring(RingAlgorithm.Aes256Gcm))

        seal_and_open_in_place_from_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.XChaCha20Poly1305))
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Gcm))
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Gcm))
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128GcmSiv))
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256GcmSiv))
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Siv))
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Siv))
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon128))
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon128a))
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon80pq))
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysI128))
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysI256))
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysII128))
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysII256))
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Eax))
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Eax))
            
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.ChaCha20Poly1305Ieft))
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.XChaCha20Poly1305Ieft))
        # seal_and_open_in_place_from_no_block_index(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.Aes256Gcm))

        seal_and_open_in_place_from_no_block_index(self, CipherMeta.Orion(OrionAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_from_no_block_index(self, CipherMeta.Orion(OrionAlgorithm.XChaCha20Poly1305))

    def seal_and_open_in_place_from_no_aad(self):
        seal_and_open_in_place_from_no_aad(self, CipherMeta.Ring(RingAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_from_no_aad(self, CipherMeta.Ring(RingAlgorithm.Aes128Gcm))
        seal_and_open_in_place_from_no_aad(self, CipherMeta.Ring(RingAlgorithm.Aes256Gcm))

        seal_and_open_in_place_from_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_from_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.XChaCha20Poly1305))
        seal_and_open_in_place_from_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Gcm))
        seal_and_open_in_place_from_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Gcm))
        seal_and_open_in_place_from_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128GcmSiv))
        seal_and_open_in_place_from_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256GcmSiv))
        seal_and_open_in_place_from_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Siv))
        seal_and_open_in_place_from_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Siv))
        seal_and_open_in_place_from_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon128))
        seal_and_open_in_place_from_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon128a))
        seal_and_open_in_place_from_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon80pq))
        seal_and_open_in_place_from_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysI128))
        seal_and_open_in_place_from_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysI256))
        seal_and_open_in_place_from_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysII128))
        seal_and_open_in_place_from_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysII256))
        seal_and_open_in_place_from_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Eax))
        seal_and_open_in_place_from_no_aad(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Eax))
            
        seal_and_open_in_place_from_no_aad(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_from_no_aad(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.ChaCha20Poly1305Ieft))
        seal_and_open_in_place_from_no_aad(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.XChaCha20Poly1305Ieft))
        # seal_and_open_in_place_from_no_aad(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.Aes256Gcm))

        seal_and_open_in_place_from_no_aad(self, CipherMeta.Orion(OrionAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_from_no_aad(self, CipherMeta.Orion(OrionAlgorithm.XChaCha20Poly1305))

    def test_seal_and_open_in_place_file(self):
        seal_and_open_in_place_file(self, CipherMeta.Ring(RingAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_file(self, CipherMeta.Ring(RingAlgorithm.Aes128Gcm))
        seal_and_open_in_place_file(self, CipherMeta.Ring(RingAlgorithm.Aes256Gcm))

        seal_and_open_in_place_file(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_file(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.XChaCha20Poly1305))
        seal_and_open_in_place_file(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Gcm))
        seal_and_open_in_place_file(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Gcm))
        seal_and_open_in_place_file(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128GcmSiv))
        seal_and_open_in_place_file(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256GcmSiv))
        seal_and_open_in_place_file(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Siv))
        seal_and_open_in_place_file(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Siv))
        seal_and_open_in_place_file(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon128))
        seal_and_open_in_place_file(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon128a))
        seal_and_open_in_place_file(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Ascon80pq))
        seal_and_open_in_place_file(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysI128))
        seal_and_open_in_place_file(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysI256))
        seal_and_open_in_place_file(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysII128))
        seal_and_open_in_place_file(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.DeoxysII256))
        seal_and_open_in_place_file(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes128Eax))
        seal_and_open_in_place_file(self, CipherMeta.RustCrypto(RustCryptoAlgorithm.Aes256Eax))
            
        seal_and_open_in_place_file(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_file(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.ChaCha20Poly1305Ieft))
        seal_and_open_in_place_file(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.XChaCha20Poly1305Ieft))
        # seal_and_open_in_place_file(self, CipherMeta.Sodiumoxide(SodiumoxideAlgorithm.Aes256Gcm))

        seal_and_open_in_place_file(self, CipherMeta.Orion(OrionAlgorithm.ChaCha20Poly1305))
        seal_and_open_in_place_file(self, CipherMeta.Orion(OrionAlgorithm.XChaCha20Poly1305))

if __name__ == "__main__":
    unittest.main()
