# This is the most performant way to use it as it will not copy bytes to the buffer nor allocate new memory for plaintext and ciphertext.

from rencrypt import Cipher, CipherMeta, RingAlgorithm
import os
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

if __name__ == "__main__":
    try:
        setup_memory_limit()

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

        # we create a buffer based on plaintext block len of 4096
        # the actual buffer needs to be a bit larger as the ciphertext also includes the tag and nonce
        plaintext_len = 4096
        ciphertext_len = cipher_meta.ciphertext_len(plaintext_len)
        buf = np.array([0] * ciphertext_len, dtype=np.uint8)
        # for security reasons we lock the memory of the buffer so it won't be swapped to disk, because it contains plaintext after decryption
        mlock(buf)

        aad = b"AAD"

        # put some plaintext in the buffer, it would be ideal if you can directly collect the data into the buffer without allocating new memory
        # but for the sake of example we will allocate and copy the data
        plaintext = bytearray(os.urandom(plaintext_len))
        # for security reasons we lock the memory of the plaintext so it won't be swapped to disk
        mlock(plaintext)
        # cipher.copy_slice is slighlty faster than buf[:plaintext_len] = plaintext, especially for large plaintext, because it copies the data in parallel
        # cipher.copy_slice takes bytes as input, cipher.copy_slice1 takes bytearray
        cipher.copy_slice(plaintext, buf)
        # encrypt it, this will encrypt in-place the data in the buffer
        print("encryping...")
        ciphertext_len = cipher.seal_in_place(buf, plaintext_len, 42, aad)
        cipertext = buf[:ciphertext_len]
        # you can do something with the ciphertext

        # decrypt it
        # if you need to copy ciphertext to buffer, we don't need to do it now as it's already in the buffer
        # cipher.copy_slice(ciphertext, buf[:len(ciphertext)])
        print("decryping...")
        plaintext_len = cipher.open_in_place(buf, ciphertext_len, 42, aad)
        plaintext2 = buf[:plaintext_len]
        # for security reasons we lock the memory of the plaintext so it won't be swapped to disk
        mlock(plaintext2)
        assert plaintext == plaintext2

    finally:
        # best practice, you should always zeroize the plaintext and keys after you are done with it (key will be zeroized when the enc object is dropped)
        zeroize1(plaintext)
        zeroize1(buf)

        munlock(buf)
        munlock(plaintext)

        print("bye!")
