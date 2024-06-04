# This is the slowest option, especially for large plaintext, because it allocates new memory for the ciphertext on encrypt and plaintext on decrypt.

from rencrypt import Cipher, CipherMeta, RingAlgorithm
import os
from zeroize import zeroize1, mlock, munlock


if __name__ == "__main__":
    try:
        # You can use also other algorithms like cipher_meta = CipherMeta.Ring(RingAlgorithm.ChaCha20Poly1305)`.
        cipher_meta = CipherMeta.Ring(RingAlgorithm.AES256GCM)
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

        aad = b"AAD"

        plaintext = bytearray(os.urandom(4096))
        # for security reasons we lock the memory of the plaintext so it won't be swapped to disk
        mlock(plaintext)

        # encrypt it, this will return the ciphertext
        print("encryping...")
        ciphertext = cipher.encrypt_from(plaintext, 42, aad)

        # decrypt it
        print("decryping...")
        plaintext2 = cipher.decrypt_from(ciphertext, 42, aad)
        # for security reasons we lock the memory of the plaintext so it won't be swapped to disk
        mlock(plaintext2)
        assert plaintext == plaintext2

    finally:
        # best practice, you should always zeroize the plaintext and keys after you are done with it (key will be zeroized when the enc object is dropped)
        zeroize1(plaintext)
        zeroize1(plaintext2)

        munlock(plaintext)
        munlock(plaintext2)

        print("bye!")
