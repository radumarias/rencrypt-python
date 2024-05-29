import datetime
import errno
import os
from rencrypt import REncrypt, Cipher


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
    # put some plaintext in the buffer
    buf[0] = 42
    aad = b"AAD"

    deltas = []
    for i in range(3):
        a = datetime.datetime.now()

        ciphertext_len = enc.encrypt_buf(buf, plaintext_len, i, aad)
        # do something with the ciphertext from buffer

        b = datetime.datetime.now()
        delta = b - a
    deltas.append(delta.total_seconds())
    average = sum(deltas, 0) / len(deltas)
    print(f"|{block_len/1024/1024} | {average:.5f}|")


def encrypt_to_buf(block_len):
    cipher = Cipher.Aes256Gcm
    key = cipher.generate_key()
    enc = REncrypt(cipher, key)

    plaintext_len, ciphertext_len, buf = enc.create_buf(block_len)
    plaintext = bytes(bytearray(plaintext_len))
    aad = b"AAD"

    deltas = []
    for i in range(3):
        a = datetime.datetime.now()

        ciphertext_len = enc.encrypt_to_buf(plaintext, buf, i, aad)
        # do something with the ciphertext from buffer

        b = datetime.datetime.now()
        delta = b - a
    deltas.append(delta.total_seconds())
    average = sum(deltas, 0) / len(deltas)
    print(f"|{block_len/1024/1024} | {average:.5f}|")


def encrypt_from(block_len):
    cipher = Cipher.Aes256Gcm
    key = cipher.generate_key()
    enc = REncrypt(cipher, key)

    plaintext = bytes(bytearray(block_len))
    aad = b"AAD"

    deltas = []
    for i in range(3):
        a = datetime.datetime.now()

        ciphertext = enc.encrypt_from(plaintext, i, aad)
        # do something with the ciphertext

        b = datetime.datetime.now()
        delta = b - a
    deltas.append(delta.total_seconds())
    average = sum(deltas, 0) / len(deltas)
    print(f"|{block_len/1024/1024} | {average:.5f}|")


def encrypt_file(path_in, path_out):
    cipher = Cipher.Aes256Gcm
    key = cipher.generate_key()
    enc = REncrypt(cipher, key)
    
    deltas = []
    for _ in range(3):
        a = datetime.datetime.now()

        silentremove(path_out)
        enc.encrypt_file(path_in, path_out, b"AAD")

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

    plaintext_len, buf = enc.get_buf()
    # put some plaintext in the buffer
    aad = b"AAD"

    deltas = []
    for i in range(3):
        a = datetime.datetime.now()

        ciphertext_len = enc.encrypt_buf(plaintext_len, i, aad)
        # do something with the ciphertext from buffer

        b = datetime.datetime.now()
        delta = b - a
    deltas.append(delta.total_seconds())
    average = sum(deltas, 0) / len(deltas)
    print(f"|{block_len/1024/1024} | {average:.5f}|")



# print("| MB    | Seconds |")
# print("| -------- | ------- |")
# encrypt_buf(32 * 1024)
# encrypt_buf(64 * 1024)
# encrypt_buf(128 * 1024)
# encrypt_buf(256 * 1024)
# encrypt_buf(512 * 1024)
# encrypt_buf(1024 * 1024)
# encrypt_buf(2 * 1024 * 1024)
# encrypt_buf(4 * 1024 * 1024)
# encrypt_buf(8 * 1024 * 1024)
# encrypt_buf(16 * 1024 * 1024)
# encrypt_buf(32 * 1024 * 1024)
# encrypt_buf(64 * 1024 * 1024)
# encrypt_buf(128 * 1024 * 1024)
# encrypt_buf(256 * 1024 * 1024)
# encrypt_buf(512 * 1024 * 1024)
# encrypt_buf(1024 * 1024 * 1024)
# encrypt_buf(2 * 1024 * 1024 * 1024)
# encrypt_buf(4 * 1024 * 1024 * 1024)
# encrypt_buf(8 * 1024 * 1024 * 1024)

# print()
# print("| MB    | Seconds |")
# print("| -------- | ------- |")
# encrypt_to_buf(32 * 1024)
# encrypt_to_buf(64 * 1024)
# encrypt_to_buf(128 * 1024)
# encrypt_to_buf(256 * 1024)
# encrypt_to_buf(512 * 1024)
# encrypt_to_buf(1024 * 1024)
# encrypt_to_buf(2 * 1024 * 1024)
# encrypt_to_buf(4 * 1024 * 1024)
# encrypt_to_buf(8 * 1024 * 1024)
# encrypt_to_buf(16 * 1024 * 1024)
# encrypt_to_buf(32 * 1024 * 1024)
# encrypt_to_buf(64 * 1024 * 1024)
# encrypt_to_buf(128 * 1024 * 1024)
# encrypt_to_buf(256 * 1024 * 1024)
# encrypt_to_buf(512 * 1024 * 1024)
# encrypt_to_buf(1024 * 1024 * 1024)
# encrypt_to_buf(2 * 1024 * 1024 * 1024)
# encrypt_to_buf(4 * 1024 * 1024 * 1024)
# encrypt_to_buf(8 * 1024 * 1024 * 1024)

# print()
# print("| MB    | Seconds |")
# print("| -------- | ------- |")
# encrypt_from(32 * 1024)
# encrypt_from(64 * 1024)
# encrypt_from(128 * 1024)
# encrypt_from(256 * 1024)
# encrypt_from(512 * 1024)
# encrypt_from(1024 * 1024)
# encrypt_from(2 * 1024 * 1024)
# encrypt_from(4 * 1024 * 1024)
# encrypt_from(8 * 1024 * 1024)
# encrypt_from(16 * 1024 * 1024)
# encrypt_from(32 * 1024 * 1024)
# encrypt_from(64 * 1024 * 1024)
# encrypt_from(128 * 1024 * 1024)
# encrypt_from(256 * 1024 * 1024)
# encrypt_from(512 * 1024 * 1024)
# encrypt_from(1024 * 1024 * 1024)
# encrypt_from(2 * 1024 * 1024 * 1024)
# encrypt_from(4 * 1024 * 1024 * 1024)
# encrypt_from(8 * 1024 * 1024 * 1024)

print()
path_in = "/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
path_out = "/tmp/test.enc"
print("| Seconds |")
print("| -------- | ------- |")
encrypt_file(path_in, path_out)
