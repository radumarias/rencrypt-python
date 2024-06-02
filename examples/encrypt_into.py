# This is a bit slower than handling data only via the buffer, especially for large plaintext,
# but there are situations when you can't directly collect the data to the buffer but have some bytes from somewhere else.

from rencrypt import REncrypt, Cipher
import os
from zeroize import zeroize1
from zeroize import zeroize_np
import numpy as np


# You can use also other ciphers like `cipher = Cipher.ChaCha20Poly1305`.
cipher = Cipher.AES256GCM
key = cipher.generate_key()
# The key is copied and the input key is zeroized for security reasons.
# The copied key will also be zeroized when the object is dropped.
enc = REncrypt(cipher, key)

# we create a buffer based on plaintext block len of 4096
# the actual buffer needs to be a bit larger as the ciphertext also includes the tag and nonce
plaintext_len = 4096
ciphertext_len = enc.ciphertext_len(plaintext_len)
buf = np.array([0] * ciphertext_len, dtype=np.uint8)

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

# best practice, you should always zeroize the plaintext and keys after you are done with it (key will be zeroized when the enc object is dropped)
zeroize1(plaintext)
zeroize_np(plaintext2)
zeroize_np(buf)

print("bye!")