import datetime
import errno
import os
from rencrypt import Cipher, CipherMeta, RingAlgorithm
import hashlib
from pathlib import Path
import shutil
import io
import numpy as np


def hash(bytes_in):
    hash_algo = hashlib.sha256()
    hash_algo.update(bytes_in)
    return hash_algo.hexdigest()


def read_file_in_chunks(file_path, buf):
    with open(file_path, "rb") as file:
        buffered_reader = io.BufferedReader(file, buffer_size=len(buf))
        while True:
            read = buffered_reader.readinto(buf)
            if read == 0:
                break
            yield read


def get_file_size(file_path):
    try:
        size = os.path.getsize(file_path)
        return size
    except FileNotFoundError:
        print(f"File {file_path} not found.")
    except Exception as e:
        print(f"Error retrieving size of file {file_path}: {e}")
        return None


def delete_file(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        print(f"File {path} not found.")
    except PermissionError:
        print(f"Permission denied to delete {path}.")
    except Exception as e:
        print(f"Error deleting file {path}: {e}")


def delete_dir(path):
    if os.path.exists(path):
        shutil.rmtree(path)
    else:
        print(f"Directory {path} does not exist.")


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


def encrypt(block_len):
    cipher_meta = CipherMeta.Ring(RingAlgorithm.AES256GCM)
    key_len = cipher_meta.key_len()
    key = bytearray(key_len)
    cipher_meta.generate_key(key)
    cipher = Cipher(cipher_meta, key)

    plaintext_len = block_len
    ciphertext_len = cipher.ciphertext_len(plaintext_len)
    buf = np.array([0] * ciphertext_len, dtype=np.uint8)

    plaintext = bytearray(os.urandom(plaintext_len))
    cipher.copy_slice(plaintext, buf[:plaintext_len])
    aad = b"AAD"

    deltas = []
    for i in range(3):
        a = datetime.datetime.now()

        cipher.encrypt(buf, plaintext_len, i, aad)

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {average:.5f} |")


def encrypt_from(block_len):
    cipher_meta = CipherMeta.Ring(RingAlgorithm.AES256GCM)
    key_len = cipher_meta.key_len()
    key = bytearray(key_len)
    cipher_meta.generate_key(key)
    cipher = Cipher(cipher_meta, key)

    plaintext_len = block_len
    ciphertext_len = cipher.ciphertext_len(plaintext_len)
    buf = np.array([0] * ciphertext_len, dtype=np.uint8)

    plaintext = bytearray(os.urandom(plaintext_len))
    aad = b"AAD"

    deltas = []
    for i in range(3):
        a = datetime.datetime.now()

        cipher.encrypt_from(plaintext, buf, i, aad)

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {average:.5f} |")


def encrypt_file(path_in, path_out):
    chunk_len = 256 * 1024

    key = os.urandom(32)

    cipher_meta = CipherMeta.Ring(RingAlgorithm.AES256GCM)
    key_len = cipher_meta.key_len()
    key = bytearray(key_len)
    cipher_meta.generate_key(key)
    cipher = Cipher(cipher_meta, key)

    plaintext_len = chunk_len
    ciphertext_len = cipher.ciphertext_len(plaintext_len)
    buf = np.array([0] * ciphertext_len, dtype=np.uint8)

    aad = b"AAD"

    deltas = []
    for _ in range(3):
        silentremove(path_out)

        a = datetime.datetime.now()

        with open(path_out, "wb", buffering=chunk_len + 28) as file_out:
            i = 0
            for read in read_file_in_chunks(path_in, buf[:plaintext_len]):
                ciphertext_len = cipher.encrypt(buf, read, i, aad)
                file_out.write(buf[:ciphertext_len])
                i += 1
            file_out.flush()

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    silentremove(path_out)

    average = sum(deltas, 0) / len(deltas)
    filesize = get_file_size(path_in)
    print(f"| {(filesize / 1024 / 1024):.5g} | {average:.5f} |")


def decrypt(block_len):
    cipher_meta = CipherMeta.Ring(RingAlgorithm.AES256GCM)
    key_len = cipher_meta.key_len()
    key = bytearray(key_len)
    cipher_meta.generate_key(key)
    cipher = Cipher(cipher_meta, key)

    plaintext_len = block_len
    ciphertext_len = cipher.ciphertext_len(plaintext_len)
    buf = np.array([0] * ciphertext_len, dtype=np.uint8)

    plaintext = bytearray(os.urandom(plaintext_len))
    aad = b"AAD"

    deltas = []
    for i in range(3):
        cipher.copy_slice(plaintext, buf[:plaintext_len])
        ciphertext_len = cipher.encrypt(buf, plaintext_len, i, aad)

        a = datetime.datetime.now()

        plaintext_len = cipher.decrypt(buf, ciphertext_len, i, aad)

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

        assert hash(plaintext) == hash(buf[:plaintext_len])

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {average:.5f} |")


def decrypt_from(block_len):
    cipher_meta = CipherMeta.Ring(RingAlgorithm.AES256GCM)
    key_len = cipher_meta.key_len()
    key = bytearray(key_len)
    cipher_meta.generate_key(key)
    cipher = Cipher(cipher_meta, key)

    plaintext_len = block_len
    ciphertext_len = cipher.ciphertext_len(plaintext_len)
    buf = np.array([0] * ciphertext_len, dtype=np.uint8)

    plaintext = bytearray(os.urandom(plaintext_len))
    aad = b"AAD"

    deltas = []
    for i in range(3):
        cipher.copy_slice(plaintext, buf[:plaintext_len])
        ciphertext_len = cipher.encrypt(buf, plaintext_len, i, aad)
        ciphertext = buf[:ciphertext_len]

        a = datetime.datetime.now()

        plaintext_len = cipher.decrypt_from(ciphertext, buf, i, aad)

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

        assert hash(plaintext) == hash(buf[:plaintext_len])

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {average:.5f} |")


def decrypt_file(plaintext_file, ciphertext_file):
    cipher_meta = CipherMeta.Ring(RingAlgorithm.AES256GCM)
    key_len = cipher_meta.key_len()
    key = bytearray(key_len)
    cipher_meta.generate_key(key)
    cipher = Cipher(cipher_meta, key)

    chunk_len = 256 * 1024

    plaintext_len = chunk_len
    ciphertext_len = cipher.ciphertext_len(plaintext_len)
    buf = np.array([0] * ciphertext_len, dtype=np.uint8)

    aad = b"AAD"

    tmp = ciphertext_file + ".dec"

    silentremove(ciphertext_file)

    with open(ciphertext_file, "wb", buffering=plaintext_len) as file_out:
        i = 0
        for read in read_file_in_chunks(plaintext_file, buf[:plaintext_len]):
            ciphertext_len = cipher.encrypt(buf, read, i, aad)
            file_out.write(buf[:ciphertext_len])
            i += 1
        file_out.flush()

    deltas = []
    for _ in range(3):
        silentremove(tmp)

        a = datetime.datetime.now()

        with open(tmp, "wb", buffering=plaintext_len) as file_out:
            i = 0
            for read in read_file_in_chunks(ciphertext_file, buf):
                plaintext_len2 = cipher.decrypt(buf, read, i, aad)
                file_out.write(buf[:plaintext_len2])
                i += 1
            file_out.flush()

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    compare_files_by_hash(plaintext_file, tmp)
    silentremove(ciphertext_file)
    silentremove(tmp)

    average = sum(deltas, 0) / len(deltas)
    filesize = get_file_size(plaintext_file)
    print(f"| {(filesize / 1024 / 1024):.5g} | {average:.5f} |")


def encrypt_speed_per_mb(block_len):
    cipher_meta = CipherMeta.Ring(RingAlgorithm.AES256GCM)
    key_len = cipher_meta.key_len()
    key = bytearray(key_len)
    cipher_meta.generate_key(key)
    cipher = Cipher(cipher_meta, key)

    plaintext_len = block_len
    ciphertext_len = cipher.ciphertext_len(plaintext_len)
    buf = np.array([0] * ciphertext_len, dtype=np.uint8)

    plaintext = bytearray(os.urandom(plaintext_len))
    cipher.copy_slice(plaintext, buf[:plaintext_len])
    aad = b"AAD"

    deltas = []
    for i in range(10000):
        a = datetime.datetime.now()

        cipher.encrypt(buf, plaintext_len, i, aad)

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {block_len/1024/1024/average} |")


tmp_dir = create_directory_in_home("Cipher_tmp")
sizes_mb = [
    0.03125,
    0.0625,
    0.125,
    0.25,
    0.5,
    1,
    2,
    4,
    8,
    16,
    32,
    64,
    128,
    256,
    512,
    # 1024,
    # 2 * 1024,
    # 4 * 1024,
]

print("\n encrypt")
print("| MB | Seconds |")
print("| -- | ------- |")
for size in [size for size in sizes_mb if size <= 1024]:
    encrypt(int(size * 1024 * 1024))

print("\n encrypt_from")
print("| MB | Seconds |")
print("| -- | ------- |")
for size in [size for size in sizes_mb if size <= 1024]:
    encrypt_from(int(size * 1024 * 1024))

print("\n encrypt_file")
print("| MB | Seconds |")
print("| -- | ------- |")
for size in sizes_mb:
    file_path = f"{tmp_dir}/test_{size}M.raw"
    create_file_with_size(file_path, int(size * 1024 * 1024))
    encrypt_file(file_path, file_path + ".enc")
    delete_file(file_path)

print("\n decrypt")
print("| MB | Seconds |")
print("| -- | ------- |")
for size in [size for size in sizes_mb if size <= 1024]:
    decrypt(int(size * 1024 * 1024))

print("\n decrypt_from")
print("| MB | Seconds |")
print("| -- | ------- |")
for size in [size for size in sizes_mb if size <= 1024]:
    decrypt_from(int(size * 1024 * 1024))

print("\n decrypt_file")
print("| MB | Seconds |")
print("| -- | ------- |")
for size in sizes_mb:
    file_path = f"{tmp_dir}/test_{size}M.raw"
    create_file_with_size(file_path, int(size * 1024 * 1024))
    decrypt_file(file_path, file_path + ".enc")
    delete_file(file_path)

print("\n encrypt_speed_per_mb")
print("| MB | Seconds |")
print("| -- | ------- |")
for size in [size for size in sizes_mb if size <= 16]:
    encrypt_speed_per_mb(int(size * 1024 * 1024))

delete_dir(tmp_dir)
