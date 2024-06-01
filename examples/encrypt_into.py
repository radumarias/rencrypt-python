# This is a bit slower than handling data only via the buffer, especially for large plaintext,
# but there are situations when you can't directly collect the data to the buffer but have some bytes from somewhere else.

import ctypes
from rencrypt import REncrypt, Cipher
import os

# You can use also other ciphers like `cipher = Cipher.ChaCha20Poly1305`.
cipher = Cipher.AES256GCM
key = cipher.generate_key()
# The key is copied and the input key is zeroized for security reasons.
# The copied key will also be zeroized when the object is dropped.
enc = REncrypt(cipher, key)

# we get a buffer based on block len 4096 plaintext
# the actual buffer will be 28 bytes larger as in ciphertext we also include the tag and nonce
plaintext_len, ciphertext_len, buf = enc.create_buf(4096)
aad = b"AAD"

plaintext = bytearray(os.urandom(plaintext_len))

 # encrypt it, after this will have the ciphertext in the buffer
print("encryping...")
ciphertext_len = enc.encrypt_into1(plaintext, buf, 42, aad)
cipertext = bytes(buf[:ciphertext_len])

# decrypt it
print("decryping...")
plaintext_len = enc.decrypt_into(cipertext, buf, 42, aad)
plaintext2 = buf[:plaintext_len]
assert plaintext == plaintext2

# best practice, you should always zeroize the plaintext after you are done with it
enc.zeroize(plaintext)
enc.zeroize(plaintext2)

print("bye!")