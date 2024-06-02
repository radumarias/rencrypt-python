# This is the most performant way to use it as it will not copy bytes to the buffer nor allocate new memory for plaintext and ciphertext.

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

# put some plaintext in the buffer, it would be ideal if you can directly collect the data into the buffer without allocating new memory
# but for the sake of example we will allocate and copy the data
plaintext = bytearray(os.urandom(plaintext_len))
# enc.copy_slice is slighlty faster than buf[:plaintext_len] = plaintext, especially for large plaintext, because it copies the data in parallel
# enc.copy_slice takes bytes as input, enc.copy_slice1 takes bytearray
enc.copy_slice1(plaintext, buf)
# encrypt it, this will encrypt in-place the data in the buffer
print("encryping...")
ciphertext_len = enc.encrypt(buf, plaintext_len, 42, aad)
cipertext = buf[:ciphertext_len]
# you can do something with the ciphertext

# decrypt it
# if you need to copy ciphertext to buffer, we don't need to do it now as it's already in the buffer
# enc.copy_slice(ciphertext, buf[:len(ciphertext)])
print("decryping...")
plaintext_len = enc.decrypt(buf, ciphertext_len, 42, aad)
plaintext2 = buf[:plaintext_len]
assert plaintext == plaintext2

# best practice, you should always zeroize the plaintext and keys after you are done with it (key will be zeroized when the enc object is dropped)
zeroize1(plaintext)
zeroize_np(plaintext2)
zeroize_np(buf)

print("bye!")
