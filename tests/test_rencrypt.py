import errno
import hashlib
import io
from pathlib import Path
import shutil
from rencrypt import Cipher, CipherMeta, RingAlgorithm
import os
import unittest
import numpy as np
from zeroize import zeroize1, mlock, munlock


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


class TestStringMethods(unittest.TestCase):

    def test_encrypt_aes(self):
        cipher_meta = CipherMeta.Ring(RingAlgorithm.AES256GCM)
        key_len = cipher_meta.key_len()
        key = bytearray(key_len)
        mlock(key)
        cipher_meta.generate_key(key)
        munlock(key)
        cipher = Cipher(cipher_meta, key)

        # we create a buffer based on plaintext block len of 4096
        # the actual buffer needs to be a bit larger as the ciphertext also includes the tag and nonce
        plaintext_len = 4096
        ciphertext_len = cipher.ciphertext_len(plaintext_len)
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
        ciphertext_len = cipher.encrypt(buf, plaintext_len, 42, aad)
        buf[:ciphertext_len]

        # decrypt it
        # if you need to copy ciphertext to buffer, we don't need to do it now as it's already in the buffer
        # cipher.copy_slice(ciphertext, buf[:len(ciphertext)])
        plaintext_len = cipher.decrypt(buf, ciphertext_len, 42, aad)
        plaintext2 = buf[:plaintext_len]
        self.assertEqual(plaintext, plaintext2)
        
        zeroize1(plaintext)
        zeroize1(buf)
        munlock(plaintext)
        munlock(buf)

    def test_encrypt_chacha(self):
        cipher_meta = CipherMeta.Ring(RingAlgorithm.ChaCha20Poly1305)
        key_len = cipher_meta.key_len()
        key = bytearray(key_len)
        mlock(key)
        cipher_meta.generate_key(key)
        cipher = Cipher(cipher_meta, key)

        # we create a buffer based on plaintext block len of 4096
        # the actual buffer needs to be a bit larger as the ciphertext also includes the tag and nonce
        plaintext_len = 4096
        ciphertext_len = cipher.ciphertext_len(plaintext_len)
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
        ciphertext_len = cipher.encrypt(buf, plaintext_len, 42, aad)

        # decrypt it
        # if you need to copy ciphertext to buffer, we don't need to do it now as it's already in the buffer
        # cipher.copy_slice(ciphertext, buf[:len(ciphertext)])
        plaintext_len = cipher.decrypt(buf, ciphertext_len, 42, aad)
        plaintext2 = buf[:plaintext_len]
        self.assertEqual(plaintext, plaintext2)
        
        zeroize1(plaintext)
        zeroize1(buf)
        munlock(plaintext)
        munlock(buf)

    def test_encrypt_from_aes(self):
        cipher_meta = CipherMeta.Ring(RingAlgorithm.AES256GCM)
        key_len = cipher_meta.key_len()
        key = bytearray(key_len)
        mlock(key)
        cipher_meta.generate_key(key)
        munlock(key)
        cipher = Cipher(cipher_meta, key)

        # we create a buffer based on plaintext block len of 4096
        # the actual buffer needs to be a bit larger as the ciphertext also includes the tag and nonce
        plaintext_len = 4096
        ciphertext_len = cipher.ciphertext_len(plaintext_len)
        buf = np.array([0] * ciphertext_len, dtype=np.uint8)
        mlock(buf)

        plaintext = bytearray(os.urandom(plaintext_len))
        mlock(plaintext)
        aad = b"AAD"

        # encrypt it, after this will have the ciphertext in the buffer
        ciphertext_len = cipher.encrypt_from(plaintext, buf, 42, aad)
        cipertext = bytes(buf[:ciphertext_len])

        # decrypt it
        plaintext_len = cipher.decrypt_from(cipertext, buf, 42, aad)
        plaintext2 = buf[:plaintext_len]
        self.assertEqual(plaintext, plaintext2)
        
        zeroize1(plaintext)
        zeroize1(buf)
        munlock(plaintext)
        munlock(buf)
    
    def test_encrypt_from_chacha(self):
        cipher_meta = CipherMeta.Ring(RingAlgorithm.ChaCha20Poly1305)
        key_len = cipher_meta.key_len()
        key = bytearray(key_len)
        mlock(key)
        cipher_meta.generate_key(key)
        munlock(key)
        cipher = Cipher(cipher_meta, key)

        # we create a buffer based on plaintext block len of 4096
        # the actual buffer needs to be a bit larger as the ciphertext also includes the tag and nonce
        plaintext_len = 4096
        ciphertext_len = cipher.ciphertext_len(plaintext_len)
        buf = np.array([0] * ciphertext_len, dtype=np.uint8)
        mlock(buf)

        plaintext = bytearray(os.urandom(plaintext_len))
        mlock(plaintext)
        aad = b"AAD"

        # encrypt it, after this will have the ciphertext in the buffer
        ciphertext_len = cipher.encrypt_from(plaintext, buf, 42, aad)
        cipertext = bytes(buf[:ciphertext_len])

        # decrypt it
        plaintext_len = cipher.decrypt_from(cipertext, buf, 42, aad)
        plaintext2 = buf[:plaintext_len]
        self.assertEqual(plaintext, plaintext2)
        
        zeroize1(plaintext)
        zeroize1(buf)
        munlock(plaintext)
        munlock(buf)
    
    
    def test_encrypt_file_aes(self):
        tmp_dir = create_directory_in_home("Cipher_tmp")
        fin = tmp_dir + "/" + "fin"
        fout = tmp_dir + "/" + "fout.enc"
        create_file_with_size(fin, 42 * 1024 * 1024)

        chunk_len = 256 * 1024

        cipher_meta = CipherMeta.Ring(RingAlgorithm.AES256GCM)
        key_len = cipher_meta.key_len()
        key = bytearray(key_len)
        mlock(key)
        cipher_meta.generate_key(key)
        munlock(key)
        cipher = Cipher(cipher_meta, key)
        
        # we create a buffer based on plaintext block len of 4096
        # the actual buffer needs to be a bit larger as the ciphertext also includes the tag and nonce
        plaintext_len = chunk_len
        ciphertext_len = cipher.ciphertext_len(plaintext_len)
        buf = np.array([0] * ciphertext_len, dtype=np.uint8)
        mlock(buf)

        aad = b"AAD"

        # encrypt
        with open(fout, "wb", buffering=plaintext_len) as file_out:
            i = 0
            for read in read_file_in_chunks(fin, buf[:plaintext_len]):
                ciphertext_len = cipher.encrypt(buf, read, i, aad)
                file_out.write(buf[:ciphertext_len])
                i += 1
            file_out.flush()

        # decrypt
        tmp = fout + ".dec"
        with open(tmp, "wb", buffering=plaintext_len) as file_out:
            i = 0
            for read in read_file_in_chunks(fout, buf):
                plaintext_len2 = cipher.decrypt(buf, read, i, aad)
                file_out.write(buf[:plaintext_len2])
                i += 1
            file_out.flush()

        compare_files_by_hash(fin, tmp)
        
        zeroize1(buf)
        munlock(buf)

    def test_encrypt_file_chacha(self):
        tmp_dir = create_directory_in_home("Cipher_tmp")
        fin = tmp_dir + "/" + "fin"
        fout = tmp_dir + "/" + "fout.enc"
        create_file_with_size(fin, 42 * 1024 * 1024)

        chunk_len = 256 * 1024

        cipher_meta = CipherMeta.Ring(RingAlgorithm.ChaCha20Poly1305)
        key_len = cipher_meta.key_len()
        key = bytearray(key_len)
        mlock(key)
        cipher_meta.generate_key(key)
        munlock(key)
        cipher = Cipher(cipher_meta, key)
        
        # we create a buffer based on plaintext block len of 4096
        # the actual buffer needs to be a bit larger as the ciphertext also includes the tag and nonce
        plaintext_len = chunk_len
        ciphertext_len = cipher.ciphertext_len(plaintext_len)
        buf = np.array([0] * ciphertext_len, dtype=np.uint8)
        mlock(buf)
        aad = b"AAD"

        # encrypt
        with open(fout, "wb", buffering=plaintext_len) as file_out:
            i = 0
            for read in read_file_in_chunks(fin, buf[:plaintext_len]):
                ciphertext_len = cipher.encrypt(buf, read, i, aad)
                file_out.write(buf[:ciphertext_len])
                i += 1
            file_out.flush()

        # decrypt
        tmp = fout + ".dec"
        with open(tmp, "wb", buffering=plaintext_len) as file_out:
            i = 0
            for read in read_file_in_chunks(fout, buf):
                plaintext_len2 = cipher.decrypt(buf, read, i, aad)
                file_out.write(buf[:plaintext_len2])
                i += 1
            file_out.flush()

        compare_files_by_hash(fin, tmp)
        
        zeroize1(buf)
        munlock(buf)


if __name__ == "__main__":
    unittest.main()
