# This is the slowest option, especially for large plaintext, because it allocates new memory for the ciphertext on encrypt and plaintext on decrypt.

from rencrypt import REncrypt, Cipher
import os

# You can use also other ciphers like `cipher = Cipher.ChaCha20Poly1305`.# You can use also other ciphers like `cipher = Cipher.ChaCha20Poly1305`.
cipher = Cipher.AES256GCM
key = cipher.generate_key()
enc = REncrypt(cipher, key)

aad = b"AAD"

plaintext = os.urandom(4096)

 # encrypt it, this will return the ciphertext
ciphertext = enc.encrypt_from(plaintext, 42, aad)

#decrypt it
plaintext2 = enc.decrypt_from(ciphertext, 42, aad)
assert plaintext == plaintext2