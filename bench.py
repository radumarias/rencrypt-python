import datetime
import errno
import os
from rencrypt import REncrypt, Cipher
import hashlib
from pathlib import Path
import shutil
import io


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
    cipher = Cipher.AES256GCM
    key = cipher.generate_key()
    enc = REncrypt(cipher, key)

    plaintext_len, _, buf = enc.create_buf(block_len)
    aad = b"AAD"

    deltas = []
    for i in range(3):
        plaintext = os.urandom(block_len)
        enc.copy_slice(plaintext, buf[: len(plaintext)])

        a = datetime.datetime.now()

        enc.encrypt(buf, plaintext_len, i, aad)

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {average:.5f} |")


def encrypt_speed_per_mb(block_len):
    cipher = Cipher.AES256GCM
    key = cipher.generate_key()
    enc = REncrypt(cipher, key)

    plaintext_len, _, buf = enc.create_buf(block_len)
    aad = b"AAD"

    deltas = []
    for i in range(1000):
        plaintext = os.urandom(block_len)
        enc.copy_slice(plaintext, buf[: len(plaintext)])

        a = datetime.datetime.now()

        enc.encrypt(buf, plaintext_len, i, aad)

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {block_len/1024/1024/average} |")


def encrypt_into(block_len):
    cipher = Cipher.AES256GCM
    key = cipher.generate_key()
    enc = REncrypt(cipher, key)

    plaintext_len, _, buf = enc.create_buf(block_len)
    aad = b"AAD"

    deltas = []
    for i in range(3):
        plaintext = os.urandom(plaintext_len)

        a = datetime.datetime.now()

        enc.encrypt_into(plaintext, buf, i, aad)

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {average:.5f} |")


def encrypt_from(block_len):
    cipher = Cipher.AES256GCM
    key = cipher.generate_key()
    enc = REncrypt(cipher, key)

    aad = b"AAD"

    deltas = []
    for i in range(3):
        plaintext = os.urandom(block_len)

        a = datetime.datetime.now()

        enc.encrypt_from(plaintext, i, aad)

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {average:.5f} |")


def encrypt_file2(path_in, path_out):
    cipher = Cipher.AES256GCM
    key = cipher.generate_key()
    enc = REncrypt(cipher, key)

    aad = b"AAD"

    deltas = []
    for _ in range(3):
        silentremove(path_out)

        a = datetime.datetime.now()

        enc.encrypt_file(path_in, path_out, aad)

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    silentremove(path_out)

    average = sum(deltas, 0) / len(deltas)
    filesize = get_file_size(path_in)
    print(f"| {(filesize / 1024 / 1024):.5g} | {average:.5f} |")


def encrypt_file(path_in, path_out):
    chunk_len = 256 * 1024

    key = os.urandom(32)

    cipher = Cipher.AES256GCM
    key = cipher.generate_key()
    enc = REncrypt(cipher, key)
    plaintext_len, _, buf = enc.create_buf(chunk_len)

    aad = b"AAD"

    deltas = []
    for _ in range(3):
        silentremove(path_out)

        a = datetime.datetime.now()

        with open(path_out, "wb", buffering=chunk_len + 28) as file_out:
            i = 0
            for read in read_file_in_chunks(path_in, buf[:plaintext_len]):
                ciphertext_len = enc.encrypt(buf, read, i, aad)
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
    cipher = Cipher.AES256GCM
    key = cipher.generate_key()
    enc = REncrypt(cipher, key)

    plaintext_len, ciphertext_len, buf = enc.create_buf(block_len)
    plaintext = os.urandom(plaintext_len)
    aad = b"AAD"

    deltas = []
    for i in range(3):
        buf[:plaintext_len] = plaintext
        ciphertext_len = enc.encrypt(buf, plaintext_len, i, aad)

        a = datetime.datetime.now()

        plaintext_len = enc.decrypt(buf, ciphertext_len, i, aad)

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

        assert buf[:plaintext_len] == plaintext

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {average:.5f} |")


def decrypt_into(block_len):
    cipher = Cipher.AES256GCM
    key = cipher.generate_key()
    enc = REncrypt(cipher, key)

    plaintext_len, ciphertext_len, buf = enc.create_buf(block_len)
    plaintext = os.urandom(plaintext_len)
    aad = b"AAD"

    deltas = []
    for i in range(3):
        buf[:plaintext_len] = plaintext
        ciphertext_len = enc.encrypt(buf, plaintext_len, i, aad)
        ciphertext = bytes(buf[:ciphertext_len])

        a = datetime.datetime.now()

        plaintext_len = enc.decrypt_into(ciphertext, buf, i, aad)

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

        assert buf[:plaintext_len] == plaintext

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {average:.5f} |")


def decrypt_from(block_len):
    cipher = Cipher.AES256GCM
    key = cipher.generate_key()
    enc = REncrypt(cipher, key)

    plaintext_len, ciphertext_len, buf = enc.create_buf(block_len)
    plaintext = os.urandom(plaintext_len)
    aad = b"AAD"

    buf[:plaintext_len] = plaintext
    ciphertext_len = enc.encrypt(buf, plaintext_len, 0, aad)
    ciphertext = bytes(buf[:ciphertext_len])

    deltas = []
    for _ in range(3):
        a = datetime.datetime.now()

        plaintext2 = enc.decrypt_from(ciphertext, 0, aad)

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

        assert plaintext2 == plaintext

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {average:.5f} |")


def decrypt_file(plaintext_file, ciphertext_file):
    key = os.urandom(32)

    cipher = Cipher.AES256GCM
    key = cipher.generate_key()
    enc = REncrypt(cipher, key)
    chunk_len = 256 * 1024
    plaintext_len, _, buf = enc.create_buf(chunk_len)

    aad = b"AAD"

    tmp = ciphertext_file + ".dec"

    silentremove(ciphertext_file)

    with open(ciphertext_file, "wb", buffering=plaintext_len) as file_out:
        i = 0
        for read in read_file_in_chunks(plaintext_file, buf[:plaintext_len]):
            ciphertext_len = enc.encrypt(buf, read, i, aad)
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
                plaintext_len2 = enc.decrypt(buf, read, i, aad)
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


def copy_file(fin, fout):
    chunk_len = 256 * 1024
    buf = bytearray(chunk_len)

    silentremove(fout)

    deltas = []
    for _ in range(3):

        a = datetime.datetime.now()

        with open(fout, "wb", buffering=chunk_len) as file_out:
            for read in read_file_in_chunks(fin, buf):
                file_out.write(buf[:read])
            file_out.flush()

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    silentremove(fout)

    average = sum(deltas, 0) / len(deltas)
    filesize = get_file_size(fin)
    print(f"| {(filesize / 1024 / 1024):.5g} | {average:.5f} |")


tmp_dir = create_directory_in_home("rencrypt_tmp")
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
    1024,
    2 * 1024,
    4 * 1024,
    # 8 * 1024,
    # 16 * 1024,
]

print("encrypt")
print("| MB    | Seconds |")
print("| ----- | ------- |")
encrypt(32 * 1024)
encrypt(64 * 1024)
encrypt(128 * 1024)
encrypt(256 * 1024)
encrypt(512 * 1024)
encrypt(1024 * 1024)
encrypt(2 * 1024 * 1024)
encrypt(4 * 1024 * 1024)
encrypt(8 * 1024 * 1024)
encrypt(16 * 1024 * 1024)
encrypt(32 * 1024 * 1024)
encrypt(64 * 1024 * 1024)
encrypt(128 * 1024 * 1024)
encrypt(256 * 1024 * 1024)
encrypt(512 * 1024 * 1024)
encrypt(1024 * 1024 * 1024)

print("\n encrypt_into")
print("| MB    | Seconds |")
print("| ----- | ------- |")
encrypt_into(32 * 1024)
encrypt_into(64 * 1024)
encrypt_into(128 * 1024)
encrypt_into(256 * 1024)
encrypt_into(512 * 1024)
encrypt_into(1024 * 1024)
encrypt_into(2 * 1024 * 1024)
encrypt_into(4 * 1024 * 1024)
encrypt_into(8 * 1024 * 1024)
encrypt_into(16 * 1024 * 1024)
encrypt_into(32 * 1024 * 1024)
encrypt_into(64 * 1024 * 1024)
encrypt_into(128 * 1024 * 1024)
encrypt_into(256 * 1024 * 1024)
encrypt_into(512 * 1024 * 1024)
encrypt_into(1024 * 1024 * 1024)

print("\n encrypt_from")
print("| MB    | Seconds |")
print("| ----- | ------- |")
encrypt_from(32 * 1024)
encrypt_from(64 * 1024)
encrypt_from(128 * 1024)
encrypt_from(256 * 1024)
encrypt_from(512 * 1024)
encrypt_from(1024 * 1024)
encrypt_from(2 * 1024 * 1024)
encrypt_from(4 * 1024 * 1024)
encrypt_from(8 * 1024 * 1024)
encrypt_from(16 * 1024 * 1024)
encrypt_from(32 * 1024 * 1024)
encrypt_from(64 * 1024 * 1024)
encrypt_from(128 * 1024 * 1024)
encrypt_from(256 * 1024 * 1024)
encrypt_from(512 * 1024 * 1024)
encrypt_from(1024 * 1024 * 1024)

print("\n encrypt")
print("| MB | Seconds |")
print("| -- | ------- |")
for size in [size for size in sizes_mb if size <= 1024]:
    encrypt(int(size * 1024 * 1024))

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

print("\n decrypt_into")
print("| MB    | Seconds |")
print("| ----- | ------- |")
decrypt_into(32 * 1024)
decrypt_into(64 * 1024)
decrypt_into(128 * 1024)
decrypt_into(256 * 1024)
decrypt_into(512 * 1024)
decrypt_into(1024 * 1024)
decrypt_into(2 * 1024 * 1024)
decrypt_into(4 * 1024 * 1024)
decrypt_into(8 * 1024 * 1024)
decrypt_into(16 * 1024 * 1024)
decrypt_into(32 * 1024 * 1024)
decrypt_into(64 * 1024 * 1024)
decrypt_into(128 * 1024 * 1024)
decrypt_into(256 * 1024 * 1024)
decrypt_into(512 * 1024 * 1024)
decrypt_into(1024 * 1024 * 1024)

print("\n decrypt_from")
print("| MB    | Seconds |")
print("| ----- | ------- |")
decrypt_from(32 * 1024)
decrypt_from(64 * 1024)
decrypt_from(128 * 1024)
decrypt_from(256 * 1024)
decrypt_from(512 * 1024)
decrypt_from(1024 * 1024)
decrypt_from(2 * 1024 * 1024)
decrypt_from(4 * 1024 * 1024)
decrypt_from(8 * 1024 * 1024)
decrypt_from(16 * 1024 * 1024)
decrypt_from(32 * 1024 * 1024)
decrypt_from(64 * 1024 * 1024)
decrypt_from(128 * 1024 * 1024)
decrypt_from(256 * 1024 * 1024)
decrypt_from(512 * 1024 * 1024)
# decrypt_from(1024 * 1024 * 1024)

print("\n decrypt_file")
print("| MB | Seconds |")
print("| -- | ------- |")
for size in sizes_mb:
    file_path = f"{tmp_dir}/test_{size}M.raw"
    create_file_with_size(file_path, int(size * 1024 * 1024))
    decrypt_file(file_path, file_path + ".enc")
    delete_file(file_path)

print("\n encrypt_speed_per_mb")
print("| MB    | MB/s |")
print("| ----- | ------- |")
encrypt_speed_per_mb(1024)
encrypt_speed_per_mb(2 * 1024)
encrypt_speed_per_mb(4 * 1024)
encrypt_speed_per_mb(8 * 1024)
encrypt_speed_per_mb(16 * 1024)
encrypt_speed_per_mb(32 * 1024)
encrypt_speed_per_mb(64 * 1024)
encrypt_speed_per_mb(128 * 1024)
encrypt_speed_per_mb(256 * 1024)
encrypt_speed_per_mb(512 * 1024)
encrypt_speed_per_mb(1024 * 1024)
encrypt_speed_per_mb(2 * 1024 * 1024)
encrypt_speed_per_mb(4 * 1024 * 1024)
encrypt_speed_per_mb(8 * 1024 * 1024)
encrypt_speed_per_mb(16 * 1024 * 1024)

delete_dir(tmp_dir)
