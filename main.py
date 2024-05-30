import datetime
import errno
import os
from rencrypt import REncrypt, Cipher
import hashlib


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


def encrypt_buf(block_len):
    cipher = Cipher.Aes256Gcm
    key = cipher.generate_key()
    enc = REncrypt(cipher, key)

    plaintext_len, ciphertext_len, buf = enc.create_buf(block_len)
    buf[0] = 42
    aad = b"AAD"

    deltas = []
    for i in range(3):
        plaintext = os.urandom(block_len)
        buf[: len(plaintext)] = plaintext

        a = datetime.datetime.now()

        ciphertext_len = enc.encrypt_buf(buf, plaintext_len, i, aad)
        # do something with the ciphertext from buffer

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {average:.5f} |")


def encrypt_to_buf(block_len):
    cipher = Cipher.Aes256Gcm
    key = cipher.generate_key()
    enc = REncrypt(cipher, key)

    plaintext_len, ciphertext_len, buf = enc.create_buf(block_len)
    aad = b"AAD"

    deltas = []
    for i in range(3):
        plaintext = os.urandom(plaintext_len)

        a = datetime.datetime.now()

        ciphertext_len = enc.encrypt_to_buf(plaintext, buf, i, aad)
        # do something with the ciphertext from buffer

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {average:.5f} |")


def encrypt_from(block_len):
    cipher = Cipher.Aes256Gcm
    key = cipher.generate_key()
    enc = REncrypt(cipher, key)

    aad = b"AAD"

    deltas = []
    for i in range(3):
        plaintext = os.urandom(block_len)

        a = datetime.datetime.now()

        ciphertext = enc.encrypt_from(plaintext, i, aad)
        # do something with the ciphertext

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {average:.5f} |")


def encrypt_file(path_in, path_out):
    cipher = Cipher.Aes256Gcm
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
    print(f"| {average:.5f} |")


def decrypt_buf(block_len):
    cipher = Cipher.Aes256Gcm
    key = cipher.generate_key()
    enc = REncrypt(cipher, key)

    plaintext_len, ciphertext_len, buf = enc.create_buf(block_len)
    plaintext = os.urandom(plaintext_len)
    aad = b"AAD"

    deltas = []
    for i in range(3):
        buf[:plaintext_len] = plaintext
        ciphertext_len = enc.encrypt_buf(buf, plaintext_len, i, aad)

        a = datetime.datetime.now()

        plaintext_len = enc.decrypt_buf(buf, ciphertext_len, i, aad)

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

        assert buf[:plaintext_len] == plaintext

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {average:.5f} |")


def decrypt_to_buf(block_len):
    cipher = Cipher.Aes256Gcm
    key = cipher.generate_key()
    enc = REncrypt(cipher, key)

    plaintext_len, ciphertext_len, buf = enc.create_buf(block_len)
    plaintext = os.urandom(plaintext_len)
    aad = b"AAD"

    deltas = []
    for i in range(3):
        buf[:plaintext_len] = plaintext
        ciphertext_len = enc.encrypt_buf(buf, plaintext_len, i, aad)
        ciphertext = bytes(buf[:ciphertext_len])

        a = datetime.datetime.now()

        plaintext_len = enc.decrypt_to_buf(ciphertext, buf, i, aad)

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

        assert buf[:plaintext_len] == plaintext

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {average:.5f} |")


def decrypt_from(block_len):
    cipher = Cipher.Aes256Gcm
    key = cipher.generate_key()
    enc = REncrypt(cipher, key)

    plaintext_len, ciphertext_len, buf = enc.create_buf(block_len)
    plaintext = os.urandom(plaintext_len)
    aad = b"AAD"

    buf[:plaintext_len] = plaintext
    ciphertext_len = enc.encrypt_buf(buf, plaintext_len, 0, aad)
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
    cipher = Cipher.Aes256Gcm
    key = cipher.generate_key()
    enc = REncrypt(cipher, key)
    
    aad = b"AAD"
    
    tmp = "/home/gnome/tmp/test.dec"

    silentremove(ciphertext_file)
    enc.encrypt_file(plaintext_file, ciphertext_file, aad)

    deltas = []
    for _ in range(3):
        silentremove(tmp)

        a = datetime.datetime.now()

        enc.decrypt_file(ciphertext_file, tmp, aad)

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())
    
    compare_files_by_hash(plaintext_file, tmp)
    silentremove(ciphertext_file)
    silentremove(tmp)

    average = sum(deltas, 0) / len(deltas)
    print(f"| {average:.5f} |")


print("encrypt_buf")
print("| MB    | Seconds |")
print("| ----- | ------- |")
encrypt_buf(32 * 1024)
encrypt_buf(64 * 1024)
encrypt_buf(128 * 1024)
encrypt_buf(256 * 1024)
encrypt_buf(512 * 1024)
encrypt_buf(1024 * 1024)
encrypt_buf(2 * 1024 * 1024)
encrypt_buf(4 * 1024 * 1024)
encrypt_buf(8 * 1024 * 1024)
encrypt_buf(16 * 1024 * 1024)
encrypt_buf(32 * 1024 * 1024)
encrypt_buf(64 * 1024 * 1024)
encrypt_buf(128 * 1024 * 1024)
encrypt_buf(256 * 1024 * 1024)
encrypt_buf(512 * 1024 * 1024)
encrypt_buf(1024 * 1024 * 1024)

print("\n encrypt_to_buf")
print("| MB    | Seconds |")
print("| ----- | ------- |")
encrypt_to_buf(32 * 1024)
encrypt_to_buf(64 * 1024)
encrypt_to_buf(128 * 1024)
encrypt_to_buf(256 * 1024)
encrypt_to_buf(512 * 1024)
encrypt_to_buf(1024 * 1024)
encrypt_to_buf(2 * 1024 * 1024)
encrypt_to_buf(4 * 1024 * 1024)
encrypt_to_buf(8 * 1024 * 1024)
encrypt_to_buf(16 * 1024 * 1024)
encrypt_to_buf(32 * 1024 * 1024)
encrypt_to_buf(64 * 1024 * 1024)
encrypt_to_buf(128 * 1024 * 1024)
encrypt_to_buf(256 * 1024 * 1024)
encrypt_to_buf(512 * 1024 * 1024)
encrypt_to_buf(1024 * 1024 * 1024)

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

print("\n encrypt_file")
path_in = "/home/gnome/tmp/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
path_out = "/home/gnome/tmp/test.enc"
print("| Seconds |")
print("| -------- |")
encrypt_file(path_in, path_out)

print("\n decrypt_buf")
print("| MB    | Seconds |")
print("| ----- | ------- |")
decrypt_buf(32 * 1024)
decrypt_buf(64 * 1024)
decrypt_buf(128 * 1024)
decrypt_buf(256 * 1024)
decrypt_buf(512 * 1024)
decrypt_buf(1024 * 1024)
decrypt_buf(2 * 1024 * 1024)
decrypt_buf(4 * 1024 * 1024)
decrypt_buf(8 * 1024 * 1024)
decrypt_buf(16 * 1024 * 1024)
decrypt_buf(32 * 1024 * 1024)
decrypt_buf(64 * 1024 * 1024)
decrypt_buf(128 * 1024 * 1024)
decrypt_buf(256 * 1024 * 1024)
decrypt_buf(512 * 1024 * 1024)
decrypt_buf(1024 * 1024 * 1024)

print("\n decrypt_to_buf")
print("| MB    | Seconds |")
print("| ----- | ------- |")
decrypt_to_buf(32 * 1024)
decrypt_to_buf(64 * 1024)
decrypt_to_buf(128 * 1024)
decrypt_to_buf(256 * 1024)
decrypt_to_buf(512 * 1024)
decrypt_to_buf(1024 * 1024)
decrypt_to_buf(2 * 1024 * 1024)
decrypt_to_buf(4 * 1024 * 1024)
decrypt_to_buf(8 * 1024 * 1024)
decrypt_to_buf(16 * 1024 * 1024)
decrypt_to_buf(32 * 1024 * 1024)
decrypt_to_buf(64 * 1024 * 1024)
decrypt_to_buf(128 * 1024 * 1024)
decrypt_to_buf(256 * 1024 * 1024)
decrypt_to_buf(512 * 1024 * 1024)
decrypt_to_buf(1024 * 1024 * 1024)

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
decrypt_from(1024 * 1024 * 1024)

print("\n decrypt_file")
path_in = "/home/gnome/tmp/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
path_out = "/home/gnome/tmp/test.enc"
print("| Seconds |")
print("| -------- |")
decrypt_file(path_in, path_out)
