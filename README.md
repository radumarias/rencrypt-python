# REncrypt

A Python encryption library implemented in Rust. It supports `AEAD` with `AES-GCM` and `ChaCha20Poly1305`. It uses [ring](https://crates.io/crates/ring) to handle encryption.  
If offers slightly higher speed compared to other Python libs. The API tries to be easy to use but it's more optimized for speed.

So if you want to achieve the highest possible encryption speed, consider giving it a try.

# Benchmark

Some benchmarks comparing to [PyFLocker](https://github.com/arunanshub/pyflocker), which, from other implementations, I found to be the fastest. After this there is also comparison with other implementations.

## Buffer in memory

This is useful when you keep a buffer, set your plaintext/ciphertext in there, and then encrypt/decrypt in-place that buffer. This is the most performant way to use it, because it doesn't allocate new memory.

<table>
    <thead>
        <tr>
            <th rowspan=2><strong>MB</strong></th>
            <th colspan=2>Encrypt<br>sec</th>
            <th colspan=2>Decrypt<br>sec</th>
        </tr>
        <tr>
            <th>REncrypt</th>
            <th>PyFLocker</th>
            <th>REncrypt</th>
            <th>PyFLocker</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>0.03125</td>
            <td>0.00001</td>
            <td>0.00091</td>
            <td>0.00001</td>
            <td>0.00004</td>
        </tr>
        <tr>
            <td>0.0625</td>
            <td>0.00001</td>
            <td>0.00005</td>
            <td>0.00001</td>
            <td>0.00004</td>
        </tr>
        <tr>
            <td>0.125</td>
            <td>0.00002</td>
            <td>0.00005</td>
            <td>0.00003</td>
            <td>0.00005</td>
        </tr>
        <tr>
            <td>0.25</td>
            <td>0.00004</td>
            <td>0.00008</td>
            <td>0.00005</td>
            <td>0.00009</td>
        </tr>
        <tr>
            <td>0.5</td>
            <td>0.00010</td>
            <td>0.00014</td>
            <td>0.00011</td>
            <td>0.00015</td>
        </tr>
        <tr>
            <td>1.0</td>
            <td>0.00021</td>
            <td>0.00024</td>
            <td>0.00021</td>
            <td>0.00029</td>
        </tr>
        <tr>
            <td>2.0</td>
            <td>0.00043</td>
            <td>0.00052</td>
            <td>0.00044</td>
            <td>0.00058</td>
        </tr>
        <tr>
            <td>4.0</td>
            <td>0.00089</td>
            <td>0.00098</td>
            <td>0.00089</td>
            <td>0.00117</td>
        </tr>
        <tr>
            <td>8.0</td>
            <td>0.00184</td>
            <td>0.00190</td>
            <td>0.00192</td>
            <td>0.00323</td>
        </tr>
        <tr>
            <td>16.0</td>
            <td>0.00353</td>
            <td>0.00393</td>
            <td>0.00367</td>
            <td>0.00617</td>
        </tr>
        <tr>
            <td>32.0</td>
            <td>0.00678</td>
            <td>0.00748</td>
            <td>0.00749</td>
            <td>0.01348</td>
        </tr>
        <tr>
            <td>64.0</td>
            <td>0.01361</td>
            <td>0.01461</td>
            <td>0.01460</td>
            <td>0.02697</td>
        </tr>
        <tr>
            <td>128.0</td>
            <td>0.02923</td>
            <td>0.03027</td>
            <td>0.03134</td>
            <td>0.05410</td>
        </tr>
        <tr>
            <td>256.0</td>
            <td>0.06348</td>
            <td>0.06188</td>
            <td>0.06136</td>
            <td>0.10417</td>
        </tr>
        <tr>
            <td>512.0</td>
            <td>0.11782</td>
            <td>0.13463</td>
            <td>0.12090</td>
            <td>0.21114</td>
        </tr>
        <tr>
            <td>1024.0</td>
            <td>0.25001</td>
            <td>0.24953</td>
            <td>0.25377</td>
            <td>0.42581</td>
        </tr>
    </tbody>
</table>


## File

<table>
    <thead>
        <tr>
            <th rowspan=2><strong>MB</strong></th>
            <th colspan=2>Encrypt<br>sec</th>
            <th colspan=2>Decrypt<br>sec</th>
        </tr>
        <tr>
            <th>REncrypt</th>
            <th>PyFLocker</th>
            <th>REncrypt</th>
            <th>PyFLocker</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>938.2</td>
            <td>0.69383</td>
            <td>0.76638</td>
            <td>0.67983</td>
            <td>0.93099</td>
        </tr>
    </tbody>
</table>

# Examples

You can see more in [examples](https://github.com/radumarias/rencrypt-python/tree/main/examples) directory and in [main.py](https://github.com/radumarias/rencrypt-python/tree/main/main.py) which has some benchmarks. Here are few simple examples:

## Encrypt and decrypt a buffer in memory

This is the most performant way to use it as it will not allocate new memory for plaintext and ciphertext.

```python
from rencrypt import REncrypt, Cipher
import os

# You can use also other ciphers like `cipher = Cipher.ChaCha20Poly1305`.
cipher = Cipher.AES256GCM
key = cipher.generate_key()
enc = REncrypt(cipher, key)

# we get a buffer based on block len 4096 plaintext
# the actual buffer will be 28 bytes larger as in ciphertext we also include the tag and nonce
plaintext_len, ciphertext_len, buf = enc.create_buf(4096)
aad = b"AAD"

# put some plaintext in the buffer, it would be ideal if you can directly collect the data into the buffer without allocating new memory
# but for the sake of example we will allocate the data
plaintext = os.urandom(plaintext_len)
# enc.copy_slice is slighlty faster than buf[:plaintext_len] = plaintext, especially for large plaintext
enc.copy_slice(plaintext, buf)
 # encrypt it, this will encrypt in-place the data in the buffer
 print("encryping...")
ciphertext_len = enc.encrypt_buf(buf, plaintext_len, 42, aad)
cipertext = buf[:ciphertext_len]
# do something with the ciphertext

# decrypt it
# if you need to copy ciphertext to buffer, we don't need to do it now as it's already in the buffer
# enc.copy_slice(ciphertext, buf[:len(ciphertext)])
print("decryping...")
plaintext_len = enc.decrypt_buf(buf, ciphertext_len, 42, aad)
plaintext2 = buf[:plaintext_len]
assert plaintext == plaintext2
print("bye!")
```

You can use other ciphers like `cipher = Cipher.ChaCha20Poly1305`.

## Encrypt and decrypt a file
```python
from rencrypt import REncrypt, Cipher
import hashlib

def calculate_file_hash(file_path):
    hash_algo = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_algo.update(chunk)
    return hash_algo.hexdigest()


def compare_files_by_hash(file1, file2):
    return calculate_file_hash(file1) == calculate_file_hash(file2)

file_in = "/tmp/fin"
file_out = "/tmp/fout.enc"

# You can use also other ciphers like `cipher = Cipher.ChaCha20Poly1305`.
cipher = Cipher.AES256GCM
key = cipher.generate_key()
enc = REncrypt(cipher, key)

aad = b"AAD"

# encrypt it
print("encryping...")
enc.encrypt_file(file_in, file_out, aad)

# decrypt it
print("decryping...")
enc.decrypt_file(file_out, file_in, aad)

compare_files_by_hash(file_in, file_out)
print("bye!")
```

Currently it's not possible to encrypt/decrypt to the same file. **DON'T DO IT, IT WILL COMPROMSE THE FILE**.

## Encrypt and decrypt from an arbitrary plaintext into the buffer

This is a bit slower than handling data only via the buffer, especially for large plaintext, but there are situations when you can't directly collect the data to the buffer but have some bytes from somewhere else.

```python
from rencrypt import REncrypt, Cipher
import os

# You can use also other ciphers like `cipher = Cipher.ChaCha20Poly1305`.
cipher = Cipher.AES256GCM
key = cipher.generate_key()
enc = REncrypt(cipher, key)

# we get a buffer based on block len 4096 plaintext
# the actual buffer will be 28 bytes larger as in ciphertext we also include the tag and nonce
plaintext_len, ciphertext_len, buf = enc.create_buf(4096)
aad = b"AAD"

plaintext = bytes(os.urandom(plaintext_len))

 # encrypt it, after this will have the ciphertext in the buffer
 print("encryping...")
ciphertext_len = enc.encrypt_to_buf(plaintext, buf, 42, aad)
cipertext = bytes(buf[:ciphertext_len])
# do something with the ciphertext

# decrypt it
print("decryping...")
plaintext_len = enc.decrypt_to_buf(cipertext, buf, 42, aad)
plaintext2 = buf[:plaintext_len]
assert plaintext == plaintext2
print("bye!")
```

## Encrypt and decrypt from an arbitrary plaintext without using the buffer

This is the slowest option, especially for large plaintext, because it allocates new memory for the ciphertext on encrypt and plaintext on decrypt.

```python
from rencrypt import REncrypt, Cipher
import os

# You can use also other ciphers like `cipher = Cipher.ChaCha20Poly1305`.# You can use also other ciphers like `cipher = Cipher.ChaCha20Poly1305`.
cipher = Cipher.AES256GCM
key = cipher.generate_key()
enc = REncrypt(cipher, key)

aad = b"AAD"

plaintext = os.urandom(4096)

 # encrypt it, this will return the ciphertext
 print("encryping...")
ciphertext = enc.encrypt_from(plaintext, 42, aad)

# decrypt it
print("decryping...")
plaintext2 = enc.decrypt_from(ciphertext, 42, aad)
assert plaintext == plaintext2
print("bye!")
```
# Building from source

## Browser

[![Open in Gitpod](https://gitpod.io/button/open-in-gitpod.svg)](https://gitpod.io/#https://github.com/radumarias/rencrypt-python)

[![Open Rustlings On Codespaces](https://github.com/codespaces/badge.svg)](https://github.com/codespaces/new/?repo=radumarias%2Frencrypt-python&ref=main)

## Geting sources from GitHub

```bash
git clone https://github.com/radumarias/rencrypt-python && cd rencrypt-python
```

## Compile and run

```bash
python -m venv .env
source .env/bin/activate
pip install maturin
maturin develop
python examples/encrypt_buf.py
```

# Future plans

- Add more `AES` ciphers like `AES128GCM` and `AES-GCM-SIV`
- Ability to use other crates to handle encryption like [RustCrypto](https://github.com/RustCrypto/traits)
- Maybe add support for `RSA` and `Elliptic-curve cryptography`
- Saving and loading keys from file

# Considerations

This lib hasn't been audited, but it mostly wraps `ring` crate which is a well knownlibrary, so in principle it should offer the same security level.
