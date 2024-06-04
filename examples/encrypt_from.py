# This is the slowest option, especially for large plaintext, because it allocates new memory for the ciphertext on encrypt and plaintext on decrypt.

from rencrypt import Cipher, CipherMeta, RingAlgorithm
import os
from zeroize import zeroize1
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

        aad = b"AAD"

        plaintext = bytearray(os.urandom(4096))
        # for security reasons we lock the memory of the plaintext so it won't be swapped to disk
        lock_memory(plaintext)

        # encrypt it, this will return the ciphertext
        print("encryping...")
        ciphertext = cipher.encrypt_from1(plaintext, 42, aad)

        # decrypt it
        print("decryping...")
        plaintext2 = cipher.decrypt_from1(ciphertext, 42, aad)
        # for security reasons we lock the memory of the plaintext so it won't be swapped to disk
        lock_memory(plaintext2)
        assert plaintext == plaintext2

    finally:
        # best practice, you should always zeroize the plaintext and keys after you are done with it (key will be zeroized when the enc object is dropped)
        zeroize1(plaintext)
        zeroize1(plaintext2)

        unlock_memory(plaintext)
        unlock_memory(plaintext2)

        print("bye!")
