# This is the slowest option, especially for large plaintext, because it allocates new memory for the ciphertext on encrypt and plaintext on decrypt.

import ctypes
from rencrypt import REncrypt, Cipher
import os

# You can use also other ciphers like `cipher = Cipher.ChaCha20Poly1305`.# You can use also other ciphers like `cipher = Cipher.ChaCha20Poly1305`.
cipher = Cipher.AES256GCM
key = cipher.generate_key()
# The key is copied and the input key is zeroized for security reasons.
# The copied key will also be zeroized when the object is dropped.
enc = REncrypt(cipher, key)

aad = b"AAD"

plaintext = bytearray(os.urandom(4096))

 # encrypt it, this will return the ciphertext
print("encryping...")
ciphertext = enc.encrypt_from1(plaintext, 42, aad)

# decrypt it
print("decryping...")
plaintext2 = enc.decrypt_from1(ciphertext, 42, aad)
assert plaintext == plaintext2

# best practice, you should always zeroize the plaintext after you are done with it
enc.zeroize(plaintext)
enc.zeroize(plaintext2)

print("bye!")