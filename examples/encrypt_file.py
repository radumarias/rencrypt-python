import errno
import io
import os
from pathlib import Path
import shutil
from rencrypt import Cipher, CipherMeta, RingAlgorithm
import hashlib
from zeroize import zeroize1, mlock, munlock
import numpy as np
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


def hash_file(file_path):
    hash_algo = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_algo.update(chunk)
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


if __name__ == "__main__":
    try:
        setup_memory_limit()

        tmp_dir = create_directory_in_home("rencrypt_tmp")
        fin = tmp_dir + "/" + "fin"
        fout = tmp_dir + "/" + "fout.enc"
        create_file_with_size(fin, 10 * 1024 * 1024)

        chunk_len = 256 * 1024

        # You can use also other algorithms like cipher_meta = CipherMeta.Ring(RingAlgorithm.ChaCha20Poly1305)`.
        cipher_meta = CipherMeta.Ring(RingAlgorithm.Aes256Gcm)
        key_len = cipher_meta.key_len()
        key = bytearray(key_len)
        # for security reasons we lock the memory of the key so it won't be swapped to disk
        mlock(key)
        cipher_meta.generate_key(key)
        # The key is copied and the input key is zeroized for security reasons.
        # The copied key will also be zeroized when the object is dropped.
        cipher = Cipher(cipher_meta, key)
        # it was zeroized we can unlock it
        munlock(key)

        plaintext_len = chunk_len
        ciphertext_len = cipher_meta.ciphertext_len(plaintext_len)
        buf = np.array([0] * ciphertext_len, dtype=np.uint8)
        mlock(buf)

        # use some random per file in additional authenticated data to prevent blocks from being swapped between files
        aad = os.urandom(16)

        # encrypt
        print("encryping...")
        with open(fout, "wb", buffering=plaintext_len) as file_out:
            i = 0
            for read in read_file_in_chunks(fin, buf[:plaintext_len]):
                ciphertext_len = cipher.seal_in_place(buf, read, i, aad)
                file_out.write(buf[:ciphertext_len])
                i += 1
            file_out.flush()

        # decrypt
        print("decryping...")
        tmp = fout + ".dec"
        with open(tmp, "wb", buffering=plaintext_len) as file_out:
            i = 0
            for read in read_file_in_chunks(fout, buf):
                plaintext_len2 = cipher.open_in_place(buf, read, i, aad)
                file_out.write(buf[:plaintext_len2])
                i += 1
            file_out.flush()

        assert compare_files_by_hash(fin, tmp)

        delete_dir(tmp_dir)

    finally:
        # best practice, you should always zeroize the plaintext and keys after you are done with it (key will be zeroized when the enc object is dropped)
        # buf will containt the last block plaintext so we need to zeroize it
        zeroize1(buf)

        munlock(buf)

    print("bye!")
