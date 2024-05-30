# This is a bit slower than handling data only via the buffer, especially for large plaintext,
# but there are situations when you can't directly collect the data to the buffer but have some bytes from somewhere else.

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

plaintext = bytes(os.urandom(plaintext_len))

 # encrypt it, after this will have the ciphertext in the buffer
ciphertext_len = enc.encrypt_to_buf(plaintext, buf, 42, aad)
cipertext = bytes(buf[:ciphertext_len])
# do something with the ciphertext

#decrypt it
plaintext_len = enc.decrypt_to_buf(cipertext, buf, 42, aad)
plaintext2 = buf[:plaintext_len]
assert plaintext == plaintext2
