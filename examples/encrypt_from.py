# This is a bit slower than handling data only via the buffer, especially for large plaintext,
# but there are situations when you can't directly collect the data to the buffer but have some bytes from somewhere else.

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

        plaintext = bytearray(os.urandom(plaintext_len))
        # for security reasons we lock the memory of the plaintext so it won't be swapped to disk
        mlock(plaintext)

        # encrypt it, after this will have the ciphertext in the buffer
        print("encryping...")
        ciphertext_len = cipher.seal_in_place_from(plaintext, buf, 42, aad)
        cipertext = bytes(buf[:ciphertext_len])

        # decrypt it
        print("decryping...")
        plaintext_len = cipher.open_in_place_from(cipertext, buf, 42, aad)
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
