import errno
import hashlib
from pathlib import Path
import shutil
from rencrypt import REncrypt, Cipher
import os
import unittest

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

    def test_encrypt(self):
        # You can use also other ciphers like `cipher = Cipher.ChaCha20Poly1305`.
        cipher = Cipher.AES256GCM
        key = cipher.generate_key()
        # The key is copied and the input key is zeroized for security reasons.
        # The copied key will also be zeroized when the object is dropped.
        enc = REncrypt(cipher, key)

        # we get a buffer based on block len 4096 plaintext
        # the actual buffer will be 28 bytes larger as in ciphertext we also include the tag and nonce
        plaintext_len, ciphertext_len, buf = enc.create_buf(4096)
        aad = b"AAD"

        # put some plaintext in the buffer, it would be ideal if you can directly collect the data into the buffer without allocating new memory
        # but for the sake of example we will allocate and copy the data
        plaintext = bytearray(os.urandom(plaintext_len))
        # enc.copy_slice is slighlty faster than buf[:plaintext_len] = plaintext, especially for large plaintext, because it copies the data in parallel
        # enc.copy_slice takes bytes as input, enc.copy_slice1 takes bytearray
        enc.copy_slice1(plaintext, buf)
        # encrypt it, this will encrypt in-place the data in the buffer
        ciphertext_len = enc.encrypt(buf, plaintext_len, 42, aad)
        cipertext = buf[:ciphertext_len]
        # you can do something with the ciphertext

        # decrypt it
        # if you need to copy ciphertext to buffer, we don't need to do it now as it's already in the buffer
        # enc.copy_slice(ciphertext, buf[:len(ciphertext)])
        plaintext_len = enc.decrypt(buf, ciphertext_len, 42, aad)
        plaintext2 = buf[:plaintext_len]
        self.assertEqual(plaintext, plaintext2)

    def test_encrypt_into(self):
        # You can use also other ciphers like `cipher = Cipher.ChaCha20Poly1305`.
        cipher = Cipher.AES256GCM
        key = cipher.generate_key()
        # The key is copied and the input key is zeroized for security reasons.
        # The copied key will also be zeroized when the object is dropped.
        enc = REncrypt(cipher, key)

        # we get a buffer based on block len 4096 plaintext
        # the actual buffer will be 28 bytes larger as in ciphertext we also include the tag and nonce
        plaintext_len, ciphertext_len, buf = enc.create_buf(4096)
        aad = b"AAD"

        plaintext = bytearray(os.urandom(plaintext_len))

        # encrypt it, after this will have the ciphertext in the buffer
        ciphertext_len = enc.encrypt_into1(plaintext, buf, 42, aad)
        cipertext = bytes(buf[:ciphertext_len])

        # decrypt it
        plaintext_len = enc.decrypt_into(cipertext, buf, 42, aad)
        plaintext2 = buf[:plaintext_len]
        self.assertEqual(plaintext, plaintext2)
    
    def test_encrypt_from(self):
        # You can use also other ciphers like `cipher = Cipher.ChaCha20Poly1305`.# You can use also other ciphers like `cipher = Cipher.ChaCha20Poly1305`.
        cipher = Cipher.AES256GCM
        key = cipher.generate_key()
        # The key is copied and the input key is zeroized for security reasons.
        # The copied key will also be zeroized when the object is dropped.
        enc = REncrypt(cipher, key)

        aad = b"AAD"

        plaintext = bytearray(os.urandom(4096))

        # encrypt it, this will return the ciphertext
        ciphertext = enc.encrypt_from1(plaintext, 42, aad)

        # decrypt it
        plaintext2 = enc.decrypt_from1(ciphertext, 42, aad)
        self.assertEqual(plaintext, plaintext2)
    
    def test_encrypt_file(self):
        tmp_dir = create_directory_in_home("rencrypt_tmp")
        fin = tmp_dir + "/" + "fin"
        fout = tmp_dir + "/" + "fout.enc"
        create_file_with_size(fin, 42 * 1024 * 1024)

        chunk_len = 256 * 1024

        cipher = Cipher.AES256GCM
        key = cipher.generate_key()
        # The key is copied and the input key is zeroized for security reasons.
        # The copied key will also be zeroized when the object is dropped.
        enc = REncrypt(cipher, key)
        plaintext_len, _, buf = enc.create_buf(chunk_len)

        aad = b"AAD"

        # encrypt
        print("encryping...")
        with open(fout, "wb", buffering=plaintext_len) as file_out:
            i = 0
            for read in read_file_in_chunks(fin, buf[:plaintext_len]):
                ciphertext_len = enc.encrypt(buf, read, i, aad)
                file_out.write(buf[:ciphertext_len])
                i += 1
            file_out.flush()

        # decrypt
        print("decryping...")
        tmp = fout + ".dec"
        with open(tmp, "wb", buffering=plaintext_len) as file_out:
            i = 0
            for read in read_file_in_chunks(fout, buf):
                plaintext_len2 = enc.decrypt(buf, read, i, aad)
                file_out.write(buf[:plaintext_len2])
                i += 1
            file_out.flush()

        compare_files_by_hash(fin, tmp)


if __name__ == "__main__":
    unittest.main()
