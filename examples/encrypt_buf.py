# This is the most performant way to use it as it will not allocate new memory for plaintext and ciphertext.

from rencrypt import REncrypt, Cipher
import os

# You can use also other ciphers like `cipher = Cipher.ChaCha20Poly1305`.
cipher = Cipher.Aes256Gcm
key = cipher.generate_key()
enc = REncrypt(cipher, key)

# we get a buffer based in block len 4096 plaintext
# the actual buffer will be 28 bytes larger as in ciphertext we also include the tag and nonce
plaintext_len, ciphertext_len, buf = enc.create_buf(4096)
aad = b"AAD"

# put some plaintext in the buffer, it would be ideal if you can directly collect the data into the buffer without allocating new memory
# but for the sake of example we will allocate the data
plaintext = os.urandom(plaintext_len)
# enc.copy_slice is slighlty faster than buf[:plaintext_len] = plaintext, especially for large plaintext
enc.copy_slice(plaintext, buf)
 # encrypt it, this will encrypt in-place the data in the buffer
ciphertext_len = enc.encrypt_buf(buf, plaintext_len, 42, aad)
cipertext = buf[:ciphertext_len]
# do something with the ciphertext

#decrypt it
# if you need to copy ciphertext to buffer, we don't need to do it now as it's already in the buffer
# enc.copy_slice(ciphertext, buf[:len(ciphertext)])
plaintext_len = enc.decrypt_buf(buf, ciphertext_len, 42, aad)
plaintext2 = buf[:plaintext_len]
assert plaintext == plaintext2