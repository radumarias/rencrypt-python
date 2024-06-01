import errno
import io
import os
from rencrypt import REncrypt, Cipher
import hashlib


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


path_in = "/tmp/fin"
path_out = "/tmp/fout.enc"

chunk_len = 256 * 1024

key = os.urandom(32)

cipher = Cipher.AES256GCM
key = cipher.generate_key()
enc = REncrypt(cipher, key)
plaintext_len, _, buf = enc.create_buf(chunk_len)

aad = b"AAD"

# encrypt
print("encryping...")
silentremove(path_out)
with open(path_out, "wb", buffering=plaintext_len) as file_out:
    i = 0
    for read in read_file_in_chunks(path_in, buf[:plaintext_len]):
        ciphertext_len = enc.encrypt(buf, read, i, aad)
        file_out.write(buf[:ciphertext_len])
        i += 1
    file_out.flush()

# decrypt
print("decryping...")
tmp_path = "/tmp/fout.dec"
with open(tmp_path, "wb", buffering=plaintext_len) as file_out:
    i = 0
    for read in read_file_in_chunks(path_out, buf):
        plaintext_len2 = enc.decrypt(buf, read, i, aad)
        file_out.write(buf[:plaintext_len2])
        i += 1
    file_out.flush()

compare_files_by_hash(path_in, tmp_path)

silentremove(tmp_path)
silentremove(path_out)

print("bye!")