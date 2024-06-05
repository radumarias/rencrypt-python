# rencrypt

[![PyPI version](https://badge.fury.io/py/rencrypt.svg)](https://badge.fury.io/py/rencrypt)
[![PyPI](https://github.com/radumarias/rencrypt-python/actions/workflows/PyPI.yml/badge.svg)](https://github.com/radumarias/rencrypt-python/actions/workflows/PyPI.yml)
[![tests](https://github.com/radumarias/rencrypt-python/actions/workflows/tests.yml/badge.svg)](https://github.com/radumarias/rencrypt-python/actions/workflows/tests.yml)  

> [!WARNING]
> **This lib hasn't been audited, but it mostly wraps `ring` crate which is a well known library, so in principle at least the primitives should offer a similar level of security.  
> This is still under development. Please do not use it with sensitive data just yet. Please wait for a stable release and maybe an audit.  
> It's mostly ideal for experimental and learning projects.**

A Python encryption library implemented in Rust. It supports `AEAD` with `AES-GCM` and `ChaCha20Poly1305`. It uses [ring](https://crates.io/crates/ring) to handle encryption.  
If offers slightly higher speed compared to other Python libs, especially for small chunks of data. The API also tries to be easy to use but it's more optimized for speed than usability.

So if you want to achieve the highest possible encryption speed, consider giving it a try.

# Benchmark

Some benchmarks comparing it to [PyFLocker](https://github.com/arunanshub/pyflocker) which from my benchmarks is the fastest among other Python libs like `cryptography`, `NaCl` (`libsodium`), `PyCryptodome`

## Buffer in memory

This is useful when you keep a buffer, set your plaintext/ciphertext in there, and then encrypt/decrypt in-place in that buffer. This is the most performant way to use it, because it does't copy any bytes nor allocate new memory.  
`rencrypt` is faster on small buffers, less than few MB, `PyFLocker` is comming closer for larger buffers.

**Encrypt seconds**  
![Encrypt buffer](https://github.com/radumarias/rencrypt-python/blob/main/resources/charts/encrypt.png?raw=true)

**Decrypt seconds**  
![Decrypt buffer](https://github.com/radumarias/rencrypt-python/blob/main/resources/charts/decrypt.png?raw=true)


**Block size and duration in seconds**
<table>
    <thead>
        <tr>
            <th>MB</th>
            <th>rencrypt<br>encrypt</th>
            <th>PyFLocker<br>encrypt</th>
            <th>rencrypt<br>decrypt</th>
            <th>PyFLocker<br>decrypt</th>
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
            <td>1</td>
            <td>0.00021</td>
            <td>0.00024</td>
            <td>0.00021</td>
            <td>0.00029</td>
        </tr>
        <tr>
            <td>2</td>
            <td>0.00043</td>
            <td>0.00052</td>
            <td>0.00044</td>
            <td>0.00058</td>
        </tr>
        <tr>
            <td>4</td>
            <td>0.00089</td>
            <td>0.00098</td>
            <td>0.00089</td>
            <td>0.00117</td>
        </tr>
        <tr>
            <td>8</td>
            <td>0.00184</td>
            <td>0.00190</td>
            <td>0.00192</td>
            <td>0.00323</td>
        </tr>
        <tr>
            <td>16</td>
            <td>0.00353</td>
            <td>0.00393</td>
            <td>0.00367</td>
            <td>0.00617</td>
        </tr>
        <tr>
            <td>32</td>
            <td>0.00678</td>
            <td>0.00748</td>
            <td>0.00749</td>
            <td>0.01348</td>
        </tr>
        <tr>
            <td>64</td>
            <td>0.01361</td>
            <td>0.01461</td>
            <td>0.01460</td>
            <td>0.02697</td>
        </tr>
        <tr>
            <td>128</td>
            <td>0.02923</td>
            <td>0.03027</td>
            <td>0.03134</td>
            <td>0.05410</td>
        </tr>
        <tr>
            <td>256</td>
            <td>0.06348</td>
            <td>0.06188</td>
            <td>0.06136</td>
            <td>0.10417</td>
        </tr>
        <tr>
            <td>512</td>
            <td>0.11782</td>
            <td>0.13463</td>
            <td>0.12090</td>
            <td>0.21114</td>
        </tr>
        <tr>
            <td>1024</td>
            <td>0.25001</td>
            <td>0.24953</td>
            <td>0.25377</td>
            <td>0.42581</td>
        </tr>
    </tbody>
</table>

## File

**Encrypt seconds**  
![Encrypt file](https://github.com/radumarias/rencrypt-python/blob/main/resources/charts/encrypt-file.png?raw=true)

 **Decrypt seconds**  
![Decrypt buffer](https://github.com/radumarias/rencrypt-python/blob/main/resources/charts/decrypt-file.png?raw=true)

**File size and duration in seconds**
<table>
    <thead>
        <tr>
            <th>MB</th>
            <th>rencrypt<br>encrypt</th>
            <th>PyFLocker<br>encrypt</th>
            <th>rencrypt<br>decrypt</th>
            <th>PyFLocker<br>decrypt</th>
        </tr>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>0.031251</td>
            <td>0.00010</td>
            <td>0.00280</td>
            <td>0.00004</td>
            <td>0.00479</td>
        </tr>
        <tr>
            <td>0.062501</td>
            <td>0.00009</td>
            <td>0.00218</td>
            <td>0.00005</td>
            <td>0.00143</td>
        </tr>
        <tr>
            <td>0.125</td>
            <td>0.00020</td>
            <td>0.00212</td>
            <td>0.00014</td>
            <td>0.00129</td>
        </tr>
        <tr>
            <td>0.25</td>
            <td>0.00034</td>
            <td>0.00232</td>
            <td>0.00020</td>
            <td>0.00165</td>
        </tr>
        <tr>
            <td>0.5</td>
            <td>0.00050</td>
            <td>0.00232</td>
            <td>0.00035</td>
            <td>0.00181</td>
        </tr>
        <tr>
            <td>1</td>
            <td>0.00087</td>
            <td>0.00356</td>
            <td>0.00065</td>
            <td>0.00248</td>
        </tr>
        <tr>
            <td>2</td>
            <td>0.00215</td>
            <td>0.00484</td>
            <td>0.00154</td>
            <td>0.00363</td>
        </tr>
        <tr>
            <td>4</td>
            <td>0.00361</td>
            <td>0.00765</td>
            <td>0.00301</td>
            <td>0.00736</td>
        </tr>
        <tr>
            <td>8</td>
            <td>0.00688</td>
            <td>0.01190</td>
            <td>0.00621</td>
            <td>0.00876</td>
        </tr>
        <tr>
            <td>16</td>
            <td>0.01503</td>
            <td>0.02097</td>
            <td>0.01202</td>
            <td>0.01583</td>
        </tr>
        <tr>
            <td>32</td>
            <td>0.02924</td>
            <td>0.03642</td>
            <td>0.02563</td>
            <td>0.02959</td>
        </tr>
        <tr>
            <td>64</td>
            <td>0.05737</td>
            <td>0.06473</td>
            <td>0.04431</td>
            <td>0.05287</td>
        </tr>
        <tr>
            <td>128</td>
            <td>0.11098</td>
            <td>0.12646</td>
            <td>0.08944</td>
            <td>0.09926</td>
        </tr>
        <tr>
            <td>256</td>
            <td>0.22964</td>
            <td>0.24716</td>
            <td>0.17402</td>
            <td>0.19420</td>
        </tr>
        <tr>
            <td>512</td>
            <td>0.43506</td>
            <td>0.46444</td>
            <td>0.38143</td>
            <td>0.38242</td>
        </tr>
        <tr>
            <td>1024</td>
            <td>0.97147</td>
            <td>0.95803</td>
            <td>0.78137</td>
            <td>0.87363</td>
        </tr>
        <tr>
            <td>2048</td>
            <td>2.07143</td>
            <td>2.10766</td>
            <td>1.69471</td>
            <td>2.99210</td>
        </tr>
        <tr>
            <td>4096</td>
            <td>4.85395</td>
            <td>4.69722</td>
            <td>5.40580</td>
            <td>8.73779</td>
        </tr>
        <tr>
            <td>8192</td>
            <td>10.76984</td>
            <td>11.76741</td>
            <td>10.29253</td>
            <td>21.00636</td>
        </tr>
        <tr>
            <td>16384</td>
            <td>21.84490</td>
            <td>26.27385</td>
            <td>39.56230</td>
            <td>43.55530</td>
        </tr>
    </tbody>
</table>

# Usage

There are two ways in which you can use the lib, the first one is a bit faster, the second offers a bit more flexible way to use it sacrificing a bit of performance.

1. **With a buffer in memory**: using `encrypt()`/`decrypt()`, is useful when you keep a buffer (or have it from somewhere), set your plaintext/ciphertext in there, and then encrypt/decrypt in-place in that buffer. This is the most performant way to use it, because it does't copy any bytes nor allocate new memory.  
**The buffer has to be a `numpy array`**, so that it's easier for you to collect data with slices that reference to underlying data. This is because the whole buffer needs to be the size of ciphertext (which is plaintext_len + tag_len + nonce_len) but you may pass a slice of the buffer to a BufferedReader to `read_into()` the plaintext.  
If you can directly collect the data to that buffer, like `BufferedReader.read_into()`, **this is the preffered way to go**.
2. **From some bytes into the buffer**: using `encrypt_into()`/`decrypt_into()`, when you have some arbitrary data that you want to work with. It will first copy those bytes to the buffer then do the operation in-place in the buffer. This is a bit slower, especially for large data, because it first needs to copy the bytes to the buffer.

## Encryption provider

You will notice in the examples we initiate the `Cipher` from something like this `cipher_meta = CipherMeta.Ring(RingAlgorithm.AES256GCM)`. The first part `CipherMeta.Ring` is the encryption provider, for now it's only one but in the future we will add more. The last part is the algorithm for that provider, in this case `AES256GCM`. Each provier might expose specific algorithms.

# Security

**For security reasons it's a good practice to lock the memory with `mlock()` in which you keep sensitive data like passwords or encrryption keys, or any other plaintext sensitive content.**  
In the examples below you will see how to do it

# Examples

You can see more in [examples](https://github.com/radumarias/rencrypt-python/tree/main/examples) directory and in [bench.py](https://github.com/radumarias/rencrypt-python/tree/main/bench.py) which has some benchmarks. Here are few simple examples:

## Encrypt and decrypt with a buffer in memory

`encrypt()`/`decrypt()`

This is the most performant way to use it as it will not copy bytes to the buffer nor allocate new memory for plaintext and ciphertext.

```python
# This is the most performant way to use it as it will not copy bytes to the buffer nor allocate new memory for plaintext and ciphertext.

from rencrypt import Cipher, CipherMeta, RingAlgorithm
import os
from zeroize import zeroize1, mlock, munlock
import numpy as np


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

        # we create a buffer based on plaintext block len of 4096
        # the actual buffer needs to be a bit larger as the ciphertext also includes the tag and nonce
        plaintext_len = 4096
        ciphertext_len = cipher.ciphertext_len(plaintext_len)
        buf = np.array([0] * ciphertext_len, dtype=np.uint8)
        # for security reasons we lock the memory of the buffer so it won't be swapped to disk, because it contains plaintext after decryption
        mlock(buf)

        aad = b"AAD"

        # put some plaintext in the buffer, it would be ideal if you can directly collect the data into the buffer without allocating new memory
        # but for the sake of example we will allocate and copy the data
        plaintext = bytearray(os.urandom(plaintext_len))
        # for security reasons we lock the memory of the plaintext so it won't be swapped to disk
        mlock(plaintext)
        # cipher.copy_slice is slighlty faster than buf[:plaintext_len] = plaintext, especially for large plaintext, because it copies the data in parallel
        # cipher.copy_slice takes bytes as input, cipher.copy_slice1 takes bytearray
        cipher.copy_slice(plaintext, buf)
        # encrypt it, this will encrypt in-place the data in the buffer
        print("encryping...")
        ciphertext_len = cipher.encrypt(buf, plaintext_len, 42, aad)
        cipertext = buf[:ciphertext_len]
        # you can do something with the ciphertext

        # decrypt it
        # if you need to copy ciphertext to buffer, we don't need to do it now as it's already in the buffer
        # cipher.copy_slice(ciphertext, buf[:len(ciphertext)])
        print("decryping...")
        plaintext_len = cipher.decrypt(buf, ciphertext_len, 42, aad)
        plaintext2 = buf[:plaintext_len]
        # for security reasons we lock the memory of the plaintext so it won't be swapped to disk
        mlock(plaintext2)
        assert plaintext == plaintext2

    finally:
        # best practice, you should always zeroize the plaintext and keys after you are done with it (key will be zeroized when the enc object is dropped)
        zeroize1(plaintext)
        zeroize1(buf)

        munlock(buf)
        munlock(plaintext)

        print("bye!")
```

You can use other ciphers like `cipher = Cipher.ChaCha20Poly1305`.

## Encrypt and decrypt a file

```python
import errno
import io
import os
from pathlib import Path
import shutil
from rencrypt import Cipher, CipherMeta, RingAlgorithm
import hashlib
from zeroize import zeroize1, mlock, munlock
import numpy as np


def read_file_in_chunks(file_path, buf):
    with open(file_path, "rb") as file:
        buffered_reader = io.BufferedReader(file, buffer_size=len(buf))
        while True:
            read = buffered_reader.readinto(buf)
            if read == 0:
                break
            yield read


def hash_file(file_path):
    hash_algo = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_algo.update(chunk)
    return hash_algo.hexdigest()


def compare_files_by_hash(file1, file2):
    return hash_file(file1) == hash_file(file2)


def silentremove(filename):
    try:
        os.remove(filename)
    except OSError as e:  # this would be "except OSError, e:" before Python 2.6
        if e.errno != errno.ENOENT:  # errno.ENOENT = no such file or directory
            raise  # re-raise exception if a different error occurred


def create_directory_in_home(dir_name):
    # Get the user's home directory
    home_dir = Path.home()

    # Create the full path for the new directory
    new_dir_path = home_dir / dir_name

    # Create the directory
    try:
        new_dir_path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"Error creating directory: {e}")

    return new_dir_path.absolute().__str__()


def create_file_with_size(file_path_str, size_in_bytes):
    with open(file_path_str, "wb") as f:
        for _ in range((size_in_bytes // 4096) + 1):
            f.write(os.urandom(min(4096, size_in_bytes)))
        f.flush()


def delete_dir(path):
    if os.path.exists(path):
        shutil.rmtree(path)
    else:
        print(f"Directory {path} does not exist.")


if __name__ == "__main__":
    try:
        tmp_dir = create_directory_in_home("Cipher_tmp")
        fin = tmp_dir + "/" + "fin"
        fout = tmp_dir + "/" + "fout.enc"
        create_file_with_size(fin, 10 * 1024 * 1024)

        chunk_len = 256 * 1024

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

        plaintext_len = chunk_len
        ciphertext_len = cipher.ciphertext_len(plaintext_len)
        buf = np.array([0] * ciphertext_len, dtype=np.uint8)
        mlock(buf)

        aad = b"AAD"

        # encrypt
        print("encryping...")
        with open(fout, "wb", buffering=plaintext_len) as file_out:
            i = 0
            for read in read_file_in_chunks(fin, buf[:plaintext_len]):
                ciphertext_len = cipher.encrypt(buf, read, i, aad)
                file_out.write(buf[:ciphertext_len])
                i += 1
            file_out.flush()

        # decrypt
        print("decryping...")
        tmp = fout + ".dec"
        with open(tmp, "wb", buffering=plaintext_len) as file_out:
            i = 0
            for read in read_file_in_chunks(fout, buf):
                plaintext_len2 = cipher.decrypt(buf, read, i, aad)
                file_out.write(buf[:plaintext_len2])
                i += 1
            file_out.flush()

        assert compare_files_by_hash(fin, tmp)

        delete_dir(tmp_dir)

    finally:
        # best practice, you should always zeroize the plaintext and keys after you are done with it (key will be zeroized when the enc object is dropped)
        # buf will containt the last block plaintext so we need to zeroize it
        zeroize1(buf)

        munlock(buf)

    print("bye!")
```

## Encrypt and decrypt from some bytes into the buffer

`encrypt_from()`/`decrypt_from()`

This is a bit slower than handling data only via the buffer, especially for large plaintext, but there are situations when you can't directly collect the data to the buffer but have some data from somewhere else.

```python
# This is a bit slower than handling data only via the buffer, especially for large plaintext,
# but there are situations when you can't directly collect the data to the buffer but have some bytes from somewhere else.

from rencrypt import Cipher, CipherMeta, RingAlgorithm
import os
from zeroize import zeroize1, mlock, munlock
import numpy as np


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

        # we create a buffer based on plaintext block len of 4096
        # the actual buffer needs to be a bit larger as the ciphertext also includes the tag and nonce
        plaintext_len = 4096
        ciphertext_len = cipher.ciphertext_len(plaintext_len)
        buf = np.array([0] * ciphertext_len, dtype=np.uint8)
        # for security reasons we lock the memory of the buffer so it won't be swapped to disk, because it contains plaintext after decryption
        mlock(buf)

        aad = b"AAD"

        plaintext = bytearray(os.urandom(plaintext_len))
        # for security reasons we lock the memory of the plaintext so it won't be swapped to disk
        mlock(plaintext)

        # encrypt it, after this will have the ciphertext in the buffer
        print("encryping...")
        ciphertext_len = cipher.encrypt_from(plaintext, buf, 42, aad)
        cipertext = bytes(buf[:ciphertext_len])

        # decrypt it
        print("decryping...")
        plaintext_len = cipher.decrypt_from(cipertext, buf, 42, aad)
        plaintext2 = buf[:plaintext_len]
        # for security reasons we lock the memory of the plaintext so it won't be swapped to disk
        mlock(plaintext2)
        assert plaintext == plaintext2

    finally:
        # best practice, you should always zeroize the plaintext and keys after you are done with it (key will be zeroized when the enc object is dropped)
        zeroize1(plaintext)
        zeroize1(buf)

        munlock(buf)
        munlock(plaintext)

        print("bye!")
```

# Build from source

## Browser

[![Open in Gitpod](https://gitpod.io/button/open-in-gitpod.svg)](https://gitpod.io/#https://github.com/radumarias/rencrypt-python)

[![Open in Codespaces](https://github.com/codespaces/badge.svg)](https://github.com/codespaces/new/?repo=radumarias%2Frencrypt-python&ref=main)

## Geting sources from GitHub
Skip this if you're starting it in browser.

```bash
git clone https://github.com/radumarias/rencrypt-python && cd Cipher-python
```

## Compile and run

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
To configure your current shell, you need to source
the corresponding env file under $HOME/.cargo.
This is usually done by running one of the following (note the leading DOT):
```bash
. "$HOME/.cargo/env"
```
```
python -m venv .env
source .env/bin/activate
pip install -r requirements.txt
maturin develop --release
pytest
python examples/encrypt.py
python examples/encrypt_into.py
python examples/encrypt_from.py
python examples/encrypt_file.py
python benches/bench.py
```

# More benchmarks

## Different ways to use the lib

**Encrypt**  
![Encrypt buffer](https://github.com/radumarias/rencrypt-python/blob/main/resources/charts/encrypt-all.png?raw=true)

**Decrypt**  
 ![Decrypt buffer](https://github.com/radumarias/rencrypt-python/blob/main/resources/charts/decrypt-all.png?raw=true)

**Block size and duration in seconds**
<table>
    <thead>
        <tr>
            <td>MB</td>
            <td>rencrypt<br>encrypt</td>
            <td>PyFLocker<br>encrypt update_into</td>
            <td>rencrypt<br>encrypt_from</td>
            <td>PyFLocker<br>encrypt update</td>
            <td>rencrypt<br>decrypt</td>
            <td>PyFLocker<br>decrypt update_into</td>
            <td>rencrypt<br>decrypt_from</td>
            <td>
                <div>
                    <div>PyFLocker<br>decrypt update</div>
                </div>
            </td>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>0.03125</td>
            <td>0.00001</td>
            <td>0.00091</td>
            <td>0.00001</td>
            <td>0.00009</td>
            <td>0.00001</td>
            <td>0.00004</td>
            <td>0.00001</td>
            <td>0.00005</td>
        </tr>
        <tr>
            <td>0.0625</td>
            <td>0.00001</td>
            <td>0.00005</td>
            <td>0.00002</td>
            <td>0.00005</td>
            <td>0.00001</td>
            <td>0.00004</td>
            <td>0.00002</td>
            <td>0.00008</td>
        </tr>
        <tr>
            <td>0.125</td>
            <td>0.00002</td>
            <td>0.00005</td>
            <td>0.00003</td>
            <td>0.00011</td>
            <td>0.00003</td>
            <td>0.00005</td>
            <td>0.00003</td>
            <td>0.00013</td>
        </tr>
        <tr>
            <td>0.25</td>
            <td>0.00004</td>
            <td>0.00008</td>
            <td>0.00007</td>
            <td>0.00019</td>
            <td>0.00005</td>
            <td>0.00009</td>
            <td>0.00007</td>
            <td>0.00023</td>
        </tr>
        <tr>
            <td>0.5</td>
            <td>0.0001</td>
            <td>0.00014</td>
            <td>0.00015</td>
            <td>0.00035</td>
            <td>0.00011</td>
            <td>0.00015</td>
            <td>0.00014</td>
            <td>0.00043</td>
        </tr>
        <tr>
            <td>1</td>
            <td>0.00021</td>
            <td>0.00024</td>
            <td>0.0008</td>
            <td>0.00082</td>
            <td>0.00021</td>
            <td>0.00029</td>
            <td>0.00044</td>
            <td>0.00103</td>
        </tr>
        <tr>
            <td>2</td>
            <td>0.00043</td>
            <td>0.00052</td>
            <td>0.00082</td>
            <td>0.00147</td>
            <td>0.00044</td>
            <td>0.00058</td>
            <td>0.00089</td>
            <td>0.00176</td>
        </tr>
        <tr>
            <td>4</td>
            <td>0.00089</td>
            <td>0.00098</td>
            <td>0.00174</td>
            <td>0.00284</td>
            <td>0.00089</td>
            <td>0.00117</td>
            <td>0.0013</td>
            <td>0.0034</td>
        </tr>
        <tr>
            <td>8</td>
            <td>0.00184</td>
            <td>0.0019</td>
            <td>0.00263</td>
            <td>0.00523</td>
            <td>0.00192</td>
            <td>0.00323</td>
            <td>0.00283</td>
            <td>0.00571</td>
        </tr>
        <tr>
            <td>16</td>
            <td>0.00353</td>
            <td>0.00393</td>
            <td>0.00476</td>
            <td>0.0141</td>
            <td>0.00367</td>
            <td>0.00617</td>
            <td>0.00509</td>
            <td>0.01031</td>
        </tr>
        <tr>
            <td>32</td>
            <td>0.00678</td>
            <td>0.00748</td>
            <td>0.00904</td>
            <td>0.0244</td>
            <td>0.00749</td>
            <td>0.01348</td>
            <td>0.01014</td>
            <td>0.02543</td>
        </tr>
        <tr>
            <td>64</td>
            <td>0.01361</td>
            <td>0.01461</td>
            <td>0.01595</td>
            <td>0.05064</td>
            <td>0.0146</td>
            <td>0.02697</td>
            <td>0.0192</td>
            <td>0.05296</td>
        </tr>
        <tr>
            <td>128</td>
            <td>0.02923</td>
            <td>0.03027</td>
            <td>0.03343</td>
            <td>0.10362</td>
            <td>0.03134</td>
            <td>0.0541</td>
            <td>0.03558</td>
            <td>0.1138</td>
        </tr>
        <tr>
            <td>256</td>
            <td>0.06348</td>
            <td>0.06188</td>
            <td>0.07303</td>
            <td>0.20911</td>
            <td>0.06136</td>
            <td>0.10417</td>
            <td>0.07572</td>
            <td>0.20828</td>
        </tr>
        <tr>
            <td>512</td>
            <td>0.11782</td>
            <td>0.13463</td>
            <td>0.14283</td>
            <td>0.41929</td>
            <td>0.1209</td>
            <td>0.21114</td>
            <td>0.14434</td>
            <td>0.41463</td>
        </tr>
        <tr>
            <td>1024</td>
            <td>0.25001</td>
            <td>0.24953</td>
            <td>0.28912</td>
            <td>0.8237</td>
            <td>0.25377</td>
            <td>0.42581</td>
            <td>0.29795</td>
            <td>0.82588</td>
        </tr>
    </tbody>
</table>

## Speed throughput

`256KB` seems to be the sweet spot for buffer size that offers the max `MB/s` speed for encryption, on benchmarks that seem to be the case.
We performed `10.000` encryption operations for each size varying from `1KB` to `16MB`.

![Speed throughput](https://github.com/radumarias/rencrypt-python/blob/main/resources/charts/speed-throughput.png?raw=true)

| MB    | MB/s |
| ----- | ------- |
| 0.0009765625 | 1083 |
| 0.001953125 | 1580 |
| 0.00390625 | 2158 |
| 0.0078125 | 2873 |
| 0.015625 | 3348 |
| 0.03125 | 3731 |
| 0.0625 | 4053 |
| 0.125 | 4156 |
| <span style="color: red; font-weight: bold;">0.25</span> | <span style="color: red; font-weight: bold;">4247</span> |
| 0.5 | 4182 |
| 1.0 | 3490 |
| 2.0 | 3539 |
| 4.0 | 3684 |
| 8.0 | 3787 |
| 16.0 | 3924 |

# For the future

- Add more `AES` ciphers like `AES128-GCM` and `AES-GCM-SIV`
- Add other encryption providers like [RustCrypto](https://github.com/RustCrypto/traits) and [libsodium](https://crates.io/crates/sodiumoxide)
- Maybe add support for `RSA` and `Elliptic-curve cryptography`
- Saving and loading keys from file

# Considerations

This lib hasn't been audited, but it mostly wraps `ring` crate which is a well known library, so in principle it should offer as similar level of security.
