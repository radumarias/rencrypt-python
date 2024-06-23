# rencrypt

[![PyPI version](https://badge.fury.io/py/rencrypt.svg)](https://badge.fury.io/py/rencrypt)
[![CI](https://github.com/radumarias/rencrypt-python/actions/workflows/CI.yml/badge.svg)](https://github.com/radumarias/rencrypt-python/actions/workflows/CI.yml)

> [!WARNING]  
> **This crate hasn't been audited, but it's mostly a wrapper over several libs like `ring` (well known and audited library),`RustCrypto` (`AES-GCM` and `ChaCha20Poly1305` ciphers are audited) but also others which are NOT audited, so in principle at least the primitives should offer a similar level of security.**

A Python encryption library implemented in Rust. It supports `AEAD` with varius ciphers. It uses [ring](https://crates.io/crates/ring), [RustCrypto](https://crates.io/crates/aead) (and derivates), [sodiumoxide](https://crates.io/crates/sodiumoxide) and [orion](https://crates.io/crates/orion) to handle encryption.  
If offers slightly higher speed compared to other Python libs, especially for small chunks of data (especially the `Ring` provider with `AES-GCM` ciphers). The API also tries to be easy to use but it's more optimized for speed than usability.

So if you want to use a vast variaety of ciphers and/or achieve the highest possible encryption speed, consider giving it a try.

# Benchmark

Some benchmarks comparing it to [PyFLocker](https://github.com/arunanshub/pyflocker) which from my benchmarks is the fastest among other Python libs like `cryptography`, `NaCl` (`libsodium`), `PyCryptodome`.

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

1. **With a buffer in memory**: using `seal_in_place()`/`open_in_place()`, is useful when you keep a buffer (or have it from somewhere), set your plaintext/ciphertext in there, and then encrypt/decrypt in-place in that buffer. This is the most performant way to use it, because it does't copy any bytes nor allocate new memory.  
**The buffer has to be a `numpy array`**, so that it's easier for you to collect data with slices that reference to underlying data. This is because the whole buffer needs to be the size of ciphertext (which is plaintext_len + tag_len + nonce_len) but you may pass a slice of the buffer to a BufferedReader to `read_into()` the plaintext.  
If you can directly collect the data to that buffer, like `BufferedReader.read_into()`, **this is the preffered way to go**.
2. **From some bytes into the buffer**: using `seal_in_place_from()`/`open_in_place_from()`, when you have some arbitrary data that you want to work with. It will first copy those bytes to the buffer then do the operation in-place in the buffer. This is a bit slower, especially for large data, because it first needs to copy the bytes to the buffer.

`block_index`, `aad` and `nonce` are optional.

If `nonce` is not provided, on each encrypt operation (`seal_in_place*()`) it will generate a cryptographically secure random nonce using `ChaCha20`. You can also provide your own nonce, there is an example below.

# Security

- **The total number of invocations of the encryption functions (`seal_in_place*()`) shall not exceed `2^32`, including all nonce lengths and all instances of `Cipher` with the given key. Following this guideline, only `4,294,967,296` messages with random nonces can be encrypted under a given key. While this bound is high, it's possible to encounter in practice, and systems which might reach it should consider alternatives to purely random nonces, like a counter or a combination of a random nonce + counter.**
- **When encrypting more than one block you should provide `block_index` as it's more secure because it ensures the order of the blocks was not changed in ciphertext.**
- **When you encrypt files it's more secure to generate a random number per file and include that in AAD, this will prevent ciphertext blocks from being swapped between files.**
- **For security reasons it's a good practice to lock the memory with `mlock()` in which you keep sensitive data like passwords or encrryption keys, or any other plaintext sensitive content. Also it's important to zeroize the data when not used anymore.**  
- **In the case of [Copy-on-write fork](https://en.wikipedia.org/wiki/Copy-on-write) you need to zeroize the memory before forking the child process.**  

In the examples below you will see how to do it.

# Encryption providers and algorithms (ciphers)

You will notice in the examples we create the `Cipher` from something like this `cipher_meta = CipherMeta.Ring(RingAlgorithm.Aes256Gcm)`. The first part `CipherMeta.Ring` is the encryption provider. The last part is the algorithm for that provider, in this case `Aes256Gcm`. Each provier might expose specific algorithms.

## Providers

```rust
enum CipherMeta {
    Ring { alg: RingAlgorithm },
    RustCrypto { alg: RustCryptoAlgorithm },
    Sodiumoxide { alg: SodiumoxideAlgorithm },
    Orion { alg: OrionAlgorithm },
}
```

- `Ring`: Based on [ring](https://crates.io/crates/ring) crate. ring is focused on the implementation, testing, and optimization of a core set of cryptographic operations exposed via an easy-to-use (and hard-to-misuse) API. ring exposes a Rust API and is written in a hybrid of Rust, C, and assembly language.  
  Particular attention is being paid to making it easy to build and integrate ring into applications and higher-level frameworks, and to ensuring that ring works optimally on small devices, and eventually microcontrollers, to support Internet of Things (IoT) applications.  
  Most of the C and assembly language code in ring comes from BoringSSL, and BoringSSL is derived from OpenSSL. ring merges changes from BoringSSL regularly. Also, several changes that were developed for ring have been contributed to and integrated into BoringSSL.
- `RustCrypto`: Based on [RustCrypto](https://github.com/RustCrypto/AEADs) collection of Authenticated Encryption with Associated Data (AEAD) algorithms written in pure Rust. AEADs are high-level symmetric encryption primitives which defend against a wide range of potential attacks (i.e. IND-CCA3).
- `Sodiumoxide`: Based on [sodiumoxide](https://crates.io/crates/sodiumoxide) crate which aims to provide a type-safe and efficient Rust binding that's just as easy to use.  
  [`NaCl`](https://nacl.cr.yp.to) (pronounced "salt") is a new easy-to-use high-speed software library for network communication, encryption, decryption, signatures, etc. NaCl's goal is to provide all of the core operations needed to build higher-level cryptographic tools. Of course, other libraries already exist for these core operations. NaCl advances the state of the art by improving security, by improving usability, and by improving speed.  
  [Sodium](https://github.com/jedisct1/libsodium) is a portable, cross-compilable, installable, packageable fork of NaCl (based on the latest released upstream version nacl-20110221), with a compatible API.
- `Orion`: Based on [orion](https://crates.io/crates/orion) crate. Written in pure Rust, it aims to provide easy and usable crypto while trying to minimize the use of unsafe code. You can read more about Orion in the [wiki](https://github.com/orion-rs/orion/wiki).

## Algorithms

```rust
enum RingAlgorithm {
    ChaCha20Poly1305,
    Aes128Gcm,
    Aes256Gcm,
}
```

```rust
enum RustCryptoAlgorithm {
    ChaCha20Poly1305,
    XChaCha20Poly1305,
    Aes128Gcm,
    Aes256Gcm,
    Aes128GcmSiv,
    Aes256GcmSiv,
    Aes128Siv,
    Aes256Siv,
    Ascon128,
    Ascon128a,
    Ascon80pq,
    DeoxysI128,
    DeoxysI256,
    DeoxysII128,
    DeoxysII256,
    Aes128Eax,
    Aes256Eax,
}
```

```rust
enum SodiumoxideAlgorithm {
    ChaCha20Poly1305,
    ChaCha20Poly1305Ieft,
    XChaCha20Poly1305Ieft,
}
```

```rust
enum OrionAlgorithm {
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}
```

## Audited

**Only for `Aes128Gcm`, `Aes256Gcm` and `ChaCha20Poly1305` with `Ring` and `RustCrypto` providers underlying crates have been audited.**

- [`Aes128Gcm`/`Aes256Gcm`](https://datatracker.ietf.org/doc/html/rfc5288): If you have hardware acceleration (e.g. `AES-NI`), then `AES-GCM` provides better performance. If you do not have a hardware acceleration, `AES-GCM` is either slower than `ChaCha20Poly1305`, or it leaks your encryption keys in cache timing. With `RustCrypto` provider the underlying `aes-gcm` has received one security audit by NCC Group, with no significant findings. With `Ring` provider the underlying `ring` crate was also audited.
- [`ChaCha20Poly1305`](https://en.wikipedia.org/wiki/ChaCha20-Poly1305): Is notable for being simple and fast when implemented in pure software. The underlying `ChaCha20` stream cipher uses a simple combination of `add`, `rotate`, and `XOR` instructions (a.k.a. `"ARX"`), and the `Poly1305` hash function is likewise extremely simple. With `RustCrypto` provider the underlying `chacha20poly1305` has received one security audit by NCC Group, with no significant findings. With `Ring` provider the underlying `ring` crtate was also audited.
  If you do not have a hardware acceleration, `ChaCha20Poly1305` is faster than `AES-GCM`.
  While it hasn't received approval from certain standards bodies (i.e. NIST) the algorithm is widely used and deployed. Notably it's mandatory to implement in the Transport Layer Security (TLS) protocol. The underlying `ChaCha20` cipher is also widely used as a cryptographically secure random number generator, including internal use by the Rust standard library.
- [`XChaCha20Poly1305`](https://en.wikipedia.org/wiki/ChaCha20-Poly1305#XChaCha20-Poly1305_%E2%80%93_extended_nonce_variant): A variant of `ChaCha20Poly1305` with an extended 192-bit (24-byte) nonce.

## Not audited

**USE AT YOUR OWN RISK!**

- [`Aes128GcmSiv` / `Aes256GcmSiv`](https://en.wikipedia.org/wiki/AES-GCM-SIV): Provides nonce reuse misuse resistance. Suitable as a general purpose symmetric encryption cipher, `AES-GCM-SIV` also removes many of the "sharp edges" of `AES-GCM`, providing significantly better security bounds while simultaneously eliminating the most catastrophic risks of nonce reuse that exist in `AES-GCM`. Decryption performance is equivalent to `AES-GCM`. Encryption is marginally slower.
- [`Aes128Siv` / `Aes256Siv`](https://github.com/miscreant/meta/wiki/AES-SIV): Cipher which also provides nonce reuse misuse resistance.
- [`Ascon128` / `Ascon128a` / `Ascon80pq`](https://ascon.iaik.tugraz.at): Designed to be lightweight and easy to implement, even with added countermeasures against side-channel attacks. Ascon has been selected as new standard for lightweight cryptography in the NIST Lightweight Cryptography competition (2019–2023). Ascon has also been selected as the primary choice for lightweight authenticated encryption in the final portfolio of the CAESAR competition (2014–2019).
- [`Deoxys`](https://sites.google.com/view/deoxyscipher): Based on a 128-bit lightweight ad-hoc tweakable block cipher. It may be used in two modes to handle nonce-respecting users (`Deoxys-I`) or nonce-reusing user (`Deoxys-II`). `Deoxys-II` has been selected as first choice for the "in-depth security" portfolio of the `CAESAR` competition.
- [`Aes128Eax` / `Aes256Eax`](https://en.wikipedia.org/wiki/EAX_mode): Designed with a two-pass scheme, one pass for achieving privacy and one for authenticity for each block. `EAX` mode was submitted on October 3, 2003, to the attention of NIST in order to replace `CCM` as standard `AEAD` mode of operation, since `CCM` mode lacks some desirable attributes of `EAX` and is more complex.
- For `Sodiumoxide` provider [`ChaCha20Poly1305`](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/original_chacha20-poly1305_construction): The original `ChaCha20-Poly1305` construction can safely encrypt a pratically unlimited number of messages with the same key, without any practical limit to the size of a message (up to ~ 2^64 bytes).
- For `Sodiumoxide` provider [`ChaChaCha20Poly1305Ieft`](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/ietf_chacha20-poly1305_construction): The IETF variant of the `ChaCha20-Poly1305` construction can safely encrypt a practically unlimited number of messages, but individual messages cannot exceed 64*(2^32)-64 bytes (approximatively 256 GB).

# Examples

You can see more in [examples](https://github.com/radumarias/rencrypt-python/tree/main/examples) directory and in [bench.py](https://github.com/radumarias/rencrypt-python/tree/main/bench.py) which has some benchmarks.

**On Windows you can mlock up to 128 KB by default. If you need more you need to first call `SetProcessWorkingSetSize` to increase the `dwMinimumWorkingSetSize`.**

Here are few simple examples.

## Encrypt and decrypt with a buffer in memory

`seal_in_place()`/`open_in_place()`

This is the most performant way to use it as it will not copy bytes to the buffer nor allocate new memory for plaintext and ciphertext.

```python
from rencrypt import Cipher, CipherMeta, RingAlgorithm
import os
from zeroize import zeroize1, mlock, munlock
import numpy as np
import platform


def setup_memory_limit():
    if not platform.system() == "Windows":
        return

    import ctypes
    from ctypes import wintypes

    # Define the Windows API functions
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    GetCurrentProcess = kernel32.GetCurrentProcess
    GetCurrentProcess.restype = wintypes.HANDLE

    SetProcessWorkingSetSize = kernel32.SetProcessWorkingSetSize
    SetProcessWorkingSetSize.restype = wintypes.BOOL
    SetProcessWorkingSetSize.argtypes = [wintypes.HANDLE, ctypes.c_size_t, ctypes.c_size_t]

    # Get the handle of the current process
    current_process = GetCurrentProcess()

    # Set the working set size
    min_size = 6 * 1024 * 1024  # Minimum working set size
    max_size = 10 * 1024 * 1024  # Maximum working set size

    result = SetProcessWorkingSetSize(current_process, min_size, max_size)

    if not result:
        error_code = ctypes.get_last_error()
        error_message = ctypes.FormatError(error_code)
        raise RuntimeError(f"SetProcessWorkingSetSize failed with error code {error_code}: {error_message}")

if __name__ == "__main__":
    try:
        setup_memory_limit()

        # You can use also other algorithms like cipher_meta = CipherMeta.Ring(RingAlgorithm.ChaCha20Poly1305)`.
        cipher_meta = CipherMeta.Ring(RingAlgorithm.Aes256Gcm)
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
        ciphertext_len = cipher_meta.ciphertext_len(plaintext_len)
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
        ciphertext_len = cipher.seal_in_place(buf, plaintext_len, 42, aad)
        cipertext = buf[:ciphertext_len]
        # you can do something with the ciphertext

        # decrypt it
        # if you need to copy ciphertext to buffer, we don't need to do it now as it's already in the buffer
        # cipher.copy_slice(ciphertext, buf[:len(ciphertext)])
        print("decryping...")
        plaintext_len = cipher.open_in_place(buf, ciphertext_len, 42, aad)
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

You can use other ciphers like `cipher_meta = CipherMeta.Ring(RingAlgorithm.ChaCha20Poly1305)`.

You can also provide your own nonce that you can generate based on your contraints.

```python
from rencrypt import Cipher, CipherMeta, RingAlgorithm
import os
from zeroize import zeroize1, mlock, munlock
import numpy as np
import platform


def setup_memory_limit():
    if not platform.system() == "Windows":
        return

    import ctypes
    from ctypes import wintypes

    # Define the Windows API functions
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    GetCurrentProcess = kernel32.GetCurrentProcess
    GetCurrentProcess.restype = wintypes.HANDLE

    SetProcessWorkingSetSize = kernel32.SetProcessWorkingSetSize
    SetProcessWorkingSetSize.restype = wintypes.BOOL
    SetProcessWorkingSetSize.argtypes = [wintypes.HANDLE, ctypes.c_size_t, ctypes.c_size_t]

    # Get the handle of the current process
    current_process = GetCurrentProcess()

    # Set the working set size
    min_size = 6 * 1024 * 1024  # Minimum working set size
    max_size = 10 * 1024 * 1024  # Maximum working set size

    result = SetProcessWorkingSetSize(current_process, min_size, max_size)

    if not result:
        error_code = ctypes.get_last_error()
        error_message = ctypes.FormatError(error_code)
        raise RuntimeError(f"SetProcessWorkingSetSize failed with error code {error_code}: {error_message}")

if __name__ == "__main__":
    try:
        setup_memory_limit()

        # You can use also other algorithms like cipher_meta = CipherMeta.Ring(RingAlgorithm.ChaCha20Poly1305)`.
        cipher_meta = CipherMeta.Ring(RingAlgorithm.Aes256Gcm)
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
        ciphertext_len = cipher_meta.ciphertext_len(plaintext_len)
        buf = np.array([0] * ciphertext_len, dtype=np.uint8)
        # for security reasons we lock the memory of the buffer so it won't be swapped to disk, because it contains plaintext after decryption
        mlock(buf)

        aad = b"AAD"
        nonce = os.urandom(cipher_meta.nonce_len())

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
        ciphertext_len = cipher.seal_in_place(buf, plaintext_len, 42, aad, nonce)
        cipertext = buf[:ciphertext_len]
        # you can do something with the ciphertext

        # decrypt it
        # if you need to copy ciphertext to buffer, we don't need to do it now as it's already in the buffer
        # cipher.copy_slice(ciphertext, buf[:len(ciphertext)])
        print("decryping...")
        plaintext_len = cipher.open_in_place(buf, ciphertext_len, 42, aad, nonce)
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
import platform


def setup_memory_limit():
    if not platform.system() == "Windows":
        return

    import ctypes
    from ctypes import wintypes

    # Define the Windows API functions
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    GetCurrentProcess = kernel32.GetCurrentProcess
    GetCurrentProcess.restype = wintypes.HANDLE

    SetProcessWorkingSetSize = kernel32.SetProcessWorkingSetSize
    SetProcessWorkingSetSize.restype = wintypes.BOOL
    SetProcessWorkingSetSize.argtypes = [wintypes.HANDLE, ctypes.c_size_t, ctypes.c_size_t]

    # Get the handle of the current process
    current_process = GetCurrentProcess()

    # Set the working set size
    min_size = 6 * 1024 * 1024  # Minimum working set size
    max_size = 10 * 1024 * 1024  # Maximum working set size

    result = SetProcessWorkingSetSize(current_process, min_size, max_size)

    if not result:
        error_code = ctypes.get_last_error()
        error_message = ctypes.FormatError(error_code)
        raise RuntimeError(f"SetProcessWorkingSetSize failed with error code {error_code}: {error_message}")

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
        setup_memory_limit()

        tmp_dir = create_directory_in_home("rencrypt_tmp")
        fin = tmp_dir + "/" + "fin"
        fout = tmp_dir + "/" + "fout.enc"
        create_file_with_size(fin, 10 * 1024 * 1024)

        chunk_len = 256 * 1024

        # You can use also other algorithms like cipher_meta = CipherMeta.Ring(RingAlgorithm.ChaCha20Poly1305)`.
        cipher_meta = CipherMeta.Ring(RingAlgorithm.Aes256Gcm)
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
        ciphertext_len = cipher_meta.ciphertext_len(plaintext_len)
        buf = np.array([0] * ciphertext_len, dtype=np.uint8)
        mlock(buf)

        # use some random per file in additional authenticated data to prevent blocks from being swapped between files
        aad = os.urandom(16)

        # encrypt
        print("encryping...")
        with open(fout, "wb", buffering=plaintext_len) as file_out:
            i = 0
            for read in read_file_in_chunks(fin, buf[:plaintext_len]):
                ciphertext_len = cipher.seal_in_place(buf, read, i, aad)
                file_out.write(buf[:ciphertext_len])
                i += 1
            file_out.flush()

        # decrypt
        print("decryping...")
        tmp = fout + ".dec"
        with open(tmp, "wb", buffering=plaintext_len) as file_out:
            i = 0
            for read in read_file_in_chunks(fout, buf):
                plaintext_len2 = cipher.open_in_place(buf, read, i, aad)
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
from rencrypt import Cipher, CipherMeta, RingAlgorithm
import os
from zeroize import zeroize1, mlock, munlock
import numpy as np
import platform


def setup_memory_limit():
    if not platform.system() == "Windows":
        return

    import ctypes
    from ctypes import wintypes

    # Define the Windows API functions
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    GetCurrentProcess = kernel32.GetCurrentProcess
    GetCurrentProcess.restype = wintypes.HANDLE

    SetProcessWorkingSetSize = kernel32.SetProcessWorkingSetSize
    SetProcessWorkingSetSize.restype = wintypes.BOOL
    SetProcessWorkingSetSize.argtypes = [wintypes.HANDLE, ctypes.c_size_t, ctypes.c_size_t]

    # Get the handle of the current process
    current_process = GetCurrentProcess()

    # Set the working set size
    min_size = 6 * 1024 * 1024  # Minimum working set size
    max_size = 10 * 1024 * 1024  # Maximum working set size

    result = SetProcessWorkingSetSize(current_process, min_size, max_size)

    if not result:
        error_code = ctypes.get_last_error()
        error_message = ctypes.FormatError(error_code)
        raise RuntimeError(f"SetProcessWorkingSetSize failed with error code {error_code}: {error_message}")

if __name__ == "__main__":
    try:
        setup_memory_limit()

        # You can use also other algorithms like cipher_meta = CipherMeta.Ring(RingAlgorithm.ChaCha20Poly1305)`.
        cipher_meta = CipherMeta.Ring(RingAlgorithm.Aes256Gcm)
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
        ciphertext_len = cipher_meta.ciphertext_len(plaintext_len)
        buf = np.array([0] * ciphertext_len, dtype=np.uint8)
        # for security reasons we lock the memory of the buffer so it won't be swapped to disk, because it contains plaintext after decryption
        mlock(buf)

        aad = b"AAD"

        plaintext = bytearray(os.urandom(plaintext_len))
        # for security reasons we lock the memory of the plaintext so it won't be swapped to disk
        mlock(plaintext)

        # encrypt it, after this will have the ciphertext in the buffer
        print("encryping...")
        ciphertext_len = cipher.seal_in_place_from(plaintext, buf, 42, aad)
        cipertext = bytes(buf[:ciphertext_len])

        # decrypt it
        print("decryping...")
        plaintext_len = cipher.open_in_place_from(cipertext, buf, 42, aad)
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

## Zeroing memory before forking child process

This mitigates the problems that appears on [Copy-on-write fork](https://en.wikipedia.org/wiki/Copy-on-write). You need to zeroize the data before forking the child process.

```python
import os
from zeroize import zeroize1, mlock, munlock


if __name__ == "__main__":
    try:
        # Maximum you can mlock is 4MB
        sensitive_data = bytearray(b"Sensitive Information")
        mlock(sensitive_data)

        print("Before zeroization:", sensitive_data)

        zeroize1(sensitive_data)
        print("After zeroization:", sensitive_data)

        # Forking after zeroization to ensure no sensitive data is copied
        pid = os.fork()
        if pid == 0:
            # This is the child process
            print("Child process memory after fork:", sensitive_data)
        else:
            # This is the parent process
            os.wait()  # Wait for the child process to exit
        
        print("all good, bye!")

    finally:
        # Unlock the memory
        print("unlocking memory")
        munlock(sensitive_data)
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

```bash
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

- Generating key from password (`KDF`)
- Maybe add support for `RSA` and `Elliptic-curve cryptography`
- Saving and loading keys from file

# Considerations

This lib hasn't been audited, but it wraps `ring` crate (well known and audited library) and `RustCrypto` (`AES-GCM` and `ChaCha20Poly1305` ciphers are audited), so in principle at least the primitives should offer a similar level of security.

# Contribute

Feel free to fork it, change and use it in any way that you want. If you build something interesting and feel like sharing pull requests are always appreciated.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache License, shall be dual-licensed as above, without any additional terms or conditions.

## How to contribute

1. Fork the repo
2. Make the changes in your fork
3. Add tests for your changes, if applicable
4. `cargo build --all --all-features` and fix any issues
5. `cargo fmt --all`, you can cnofigure your IDE to do this on save [RustRover](https://www.jetbrains.com/help/rust/rustfmt.html) and [VSCode](https://code.visualstudio.com/docs/languages/rust#_formatting)
6. `cargo check --all --all-features` and fix any errors and warnings
7. `cargo clippy --all --all-features` and fix any errors
8. `cargo test --all --all-features` and fix any issues
9. `cargo bench --all --all-features` and fix any issues
10. Create a PR
11. Monitor the checks (GitHub actions runned)
12. Respond to any comments
13. In the end ideally it will be merged to `main`
