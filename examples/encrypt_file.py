# Currently it's not possible to encrypt/decrypt to the same file. **DON'T DO IT, IT WILL COMPROMSE THE FILE**.

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

file_in = "/tmp/fin"
file_out = "/tmp/fout.enc"

cipher = Cipher.AES256GCM
key = cipher.generate_key()
enc = REncrypt(cipher, key)

aad = b"AAD"

# encrypt it
enc.encrypt_file(file_in, file_out, aad)

# decrypt it
enc.decrypt_file(file_out, file_in, aad)

compare_files_by_hash(file_in, file_out)
