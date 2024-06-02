import errno
import io
import os
from pathlib import Path
import shutil
from rencrypt import REncrypt, Cipher
import hashlib
from zeroize import zeroize_np
import numpy as np


def read_file_in_chunks(file_path, buf):
    with open(file_path, "rb") as file:
        buffered_reader = io.BufferedReader(file, buffer_size=len(buf))
        while True:
            read = buffered_reader.readinto(buf)
            if read == 0:
                break
            yield read


def hash_file(file_path):
    hash_algo = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_algo.update(chunk)
    return hash_algo.hexdigest()

def hash(bytes_in):
    hash_algo = hashlib.sha256()
    hash_algo.update(bytes_in)
    return hash_algo.hexdigest()


def compare_files_by_hash(file1, file2):
    return hash_file(file1) == hash_file(file2)


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
        for _ in range((size_in_bytes // 4096) + 1):
            f.write(os.urandom(min(4096, size_in_bytes)))
        f.flush()


def delete_dir(path):
    if os.path.exists(path):
        shutil.rmtree(path)
    else:
        print(f"Directory {path} does not exist.")


tmp_dir = create_directory_in_home("rencrypt_tmp")
fin = tmp_dir + "/" + "fin"
fout = tmp_dir + "/" + "fout.enc"
create_file_with_size(fin, 10 * 1024 * 1024)

chunk_len = 256 * 1024

cipher = Cipher.AES256GCM
key = cipher.generate_key()
# The key is copied and the input key is zeroized for security reasons.
# The copied key will also be zeroized when the object is dropped.
enc = REncrypt(cipher, key)
plaintext_len = chunk_len;
ciphertext_len = enc.ciphertext_len(plaintext_len)
buf = np.array([0] * ciphertext_len, dtype=np.uint8)

aad = b"AAD"

# encrypt
print("encryping...")
h1 = bytes(32)
with open(fout, "wb", buffering=plaintext_len) as file_out:
    i = 0
    for read in read_file_in_chunks(fin, buf[:plaintext_len]):
        h1 = hash(buf[:read])
        ciphertext_len = enc.encrypt(buf, read, i, aad)
        file_out.write(buf[:ciphertext_len])
        i += 1
    file_out.flush()

# decrypt
print("decryping...")
tmp = fout + ".dec"
h2 = bytes(32)
with open(tmp, "wb", buffering=plaintext_len) as file_out:
    i = 0
    for read in read_file_in_chunks(fout, buf):
        plaintext_len2 = enc.decrypt(buf, read, i, aad)
        h2 = hash(buf[:plaintext_len2])
        file_out.write(buf[:plaintext_len2])
        i += 1
    file_out.flush()

assert compare_files_by_hash(fin, tmp)

delete_dir(tmp_dir)
# best practice, you should always zeroize the plaintext and keys after you are done with it (key will be zeroized when the enc object is dropped)
zeroize_np(buf)

print("bye!")
