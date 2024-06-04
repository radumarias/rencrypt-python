# This is a bit slower than handling data only via the buffer, especially for large plaintext,
# but there are situations when you can't directly collect the data to the buffer but have some bytes from somewhere else.

from rencrypt import Cipher, CipherMeta, RingAlgorithm
import os
from zeroize import zeroize1
from zeroize import zeroize_np
import numpy as np
import ctypes


# Load the C standard library
LIBC = ctypes.CDLL("libc.so.6")
MLOCK = LIBC.mlock
MUNLOCK = LIBC.munlock

# Define mlock and munlock argument types
MLOCK.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
MUNLOCK.argtypes = [ctypes.c_void_p, ctypes.c_size_t]


def lock_memory(buffer):
    """Locks the memory of the given buffer."""
    address = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
    size = len(buffer)
    if MLOCK(address, size) != 0:
        raise RuntimeError("Failed to lock memory")


def unlock_memory(buffer):
    """Unlocks the memory of the given buffer."""
    address = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
    size = len(buffer)
    if MUNLOCK(address, size) != 0:
        raise RuntimeError("Failed to unlock memory")


if __name__ == "__main__":
    try:
        # You can use also other algorithms like cipher_meta = CipherMeta.Ring(RingAlgorithm.ChaCha20Poly1305)`.
        cipher_meta = CipherMeta.Ring(RingAlgorithm.AES256GCM)
        key_len = cipher_meta.key_len()
        key = bytearray(key_len)
        # for security reasons we lock the memory of the key so it won't be swapped to disk
        lock_memory(key)
        cipher_meta.generate_key(key)
        # The key is copied and the input key is zeroized for security reasons.
        # The copied key will also be zeroized when the object is dropped.
        cipher = Cipher(cipher_meta, key)
        # it was zeroized we can unlock it
        unlock_memory(key)

        # we create a buffer based on plaintext block len of 4096
        # the actual buffer needs to be a bit larger as the ciphertext also includes the tag and nonce
        plaintext_len = 4096
        ciphertext_len = cipher.ciphertext_len(plaintext_len)
        buf = np.array([0] * ciphertext_len, dtype=np.uint8)
        # for security reasons we lock the memory of the buffer so it won't be swapped to disk, because it contains plaintext after decryption
        lock_memory(buf)

        aad = b"AAD"

        plaintext = bytearray(os.urandom(plaintext_len))
        # for security reasons we lock the memory of the plaintext so it won't be swapped to disk
        lock_memory(plaintext)

        # encrypt it, after this will have the ciphertext in the buffer
        print("encryping...")
        ciphertext_len = cipher.encrypt_into1(plaintext, buf, 42, aad)
        cipertext = bytes(buf[:ciphertext_len])

        # decrypt it
        print("decryping...")
        plaintext_len = cipher.decrypt_into(cipertext, buf, 42, aad)
        plaintext2 = buf[:plaintext_len]
        # for security reasons we lock the memory of the plaintext so it won't be swapped to disk
        lock_memory(plaintext2)
        assert plaintext == plaintext2

    finally:
        # best practice, you should always zeroize the plaintext and keys after you are done with it (key will be zeroized when the enc object is dropped)
        zeroize1(plaintext)
        zeroize_np(plaintext2)
        zeroize_np(buf)

        unlock_memory(key)
        unlock_memory(buf)
        unlock_memory(plaintext)
        unlock_memory(plaintext2)

        print("bye!")
