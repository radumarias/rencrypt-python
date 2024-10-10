from typing import Any, Union, Optional, Protocol


class Cipher:
    """
    A cryptographic cipher object.

    This struct provides access to a variety of cryptographic algorithms, specified by the `CipherMeta` parameter,
    and securely manages encryption keys. The `Cipher` supports encryption and decryption operations while ensuring 
    that sensitive key data is securely handled in memory.
    """
    cipher: Any
    cipher_meta: CipherMeta

    def __init__(self, cipher_meta: CipherMeta, key: Any) -> None:
        """
    Create a new cipher object with the specified algorithm and key.

    Args:
        cipher_meta (CipherMeta): Specifies the cryptographic algorithm and configuration for the cipher.
        key (bytearray or numpy array): The encryption key, which must be provided as a mutable buffer.
    
    Returns:
        Cipher: A new Cipher object ready for cryptographic operations.
    
    Raises:
        ValueError: If there is an issue initializing the cipher, such as an invalid key or algorithm.
    
    Example:
        ```python
        from your_module import Cipher, CipherMeta
    
        cipher_meta = CipherMeta.Ring(alg="AES-256-GCM")
        key = bytearray(b"your_secret_key_here")
        cipher = Cipher(cipher_meta, key)
        ```
        """

    def seal_in_place(
        self,
        buf: bytearray,
        plaintext_len: int,
        block_index: Optional[int] = None,
        aad: Optional[bytes] = None,
        nonce: Optional[bytes] = None
    ) -> int:
        """
    Encrypts data in place, writing the resulting ciphertext to the provided buffer.

    Args:
        buf (bytearray or numpy array): A mutable buffer where the encrypted data will be stored.
        plaintext_len (int): The length of the plaintext data to encrypt.
        block_index (Optional[int]): The block index to use for encryption (if applicable).
        aad (Optional[bytes]): Additional authenticated data (optional).
        nonce (Optional[bytes]): Nonce for encryption (optional).

    Returns:
        int: The total length of the resulting ciphertext, including overhead.

    Raises:
        ValueError: If encryption fails or parameters are invalid.
    """

    def seal_in_place_from(
        self,
        buf: Union[str, bytearray],
        plaintext_len: int,
        block_index: Optional[int] = None,
        aad: Optional[bytes] = None,
        nonce: Optional[bytes] = None
    ) -> int:
        """
    Encrypts the given plaintext and writes the result to the provided buffer.

    Args:
        plaintext (bytearray or numpy array): The data to encrypt.
        buf (bytearray or numpy array): The buffer to write the encrypted data into.
        block_index (Optional[int]): The block index to use for encryption (if applicable).
        aad (Optional[bytes]): Additional authenticated data (optional).
        nonce (Optional[bytes]): Nonce for encryption (optional).

    Returns:
        int: The total length of the resulting ciphertext, including overhead.

    Raises:
        ValueError: If encryption fails or parameters are invalid.
    """

    @staticmethod
    def copy_slice(src: int, buf: bytearray) -> None:
        """
        Copies data from the source to the destination buffer.

        Args:
            src (int): The source data to copy from.
            buf (bytearray): A mutable buffer to copy the data into.

        Raises:
            PyResult: If copying fails.
        """

    def open_in_place(
        self,
        buf: bytearray,
        plaintext_and_tag_and_nonce_len: int,
        block_index: Optional[int] = None,
        aad: Optional[bytes] = None
    ) -> int:
        """
        Decrypts the data in place using the provided buffer.

        Args:
            buf (bytearray or numpy array): A mutable buffer containing the ciphertext and associated data.
            plaintext_and_tag_and_nonce_len (int): The length of the plaintext, tag, and nonce.
            block_index (Optional[int]): An optional block index for additional processing.
            aad (Optional[bytes]): Additional authenticated data (AAD).

        Returns:
            int: The length of the decrypted plaintext.

        Raises:
            PyResult: If decryption fails.
        """

    def open_in_place_from(
            self,
            ciphertext_and_tag_and_nonce: bytearray,
            buf: bytearray,
            block_index: Optional[int] = None,
            aad: Optional[bytes] = None
        ) -> int:
            """
        Decrypts the provided ciphertext and tag, storing the result in the specified buffer.

        Args:
            ciphertext_and_tag_and_nonce (bytearray): The buffer containing the ciphertext, tag, and nonce.
            buf (bytearray): A mutable buffer where the decrypted plaintext will be stored.
            block_index (Optional[int]): An optional block index for additional processing.
            aad (Optional[bytes]): Additional authenticated data (AAD).

        Returns:
            int: The length of the decrypted plaintext.

        Raises:
            PyResult: If decryption fails.
        """

class RingAlgorithm:
    """
    Class containing supported algorithms in the Ring cryptography library.

    Variants:
        - ChaCha20Poly1305
        - Aes128Gcm
        - Aes256Gcm (default)
    """


class RustCryptoAlgorithm:
    """
    Enum containing supported algorithms in the RustCrypto cryptography library.

    Variants:
        - ChaCha20Poly1305
        - XChaCha20Poly1305
        - Aes128Gcm
        - Aes256Gcm (default)
        - Aes128GcmSiv
        - Aes256GcmSiv
        - Ascon128
        - Ascon128a
        - Ascon80pq
        - DeoxysI128
        - DeoxysI256
        - Aes128Eax
        - Aes256Eax
    """


class SodiumoxideAlgorithm:
    """
    Class containing supported algorithms in the Sodiumoxide cryptography library.

    Variants:
        - ChaCha20Poly1305
        - ChaCha20Poly1305Ietf (default)
        - XChaCha20Poly1305Ietf
    """


class OrionAlgorithm:
    """
    Class containing supported algorithms in the Orion cryptography library.

    Variants:
        - ChaCha20Poly1305 (default)
        - XChaCha20Poly1305
    """


class CipherMeta:
    """
    Class containing different cryptography libraries and their associated algorithms.

    Variants:
        - Ring: Uses the Ring cryptography library.
        - RustCrypto: Uses the RustCrypto cryptography library.
        - Sodiumoxide: Uses the Sodiumoxide cryptography library.
        - Orion: Uses the Orion cryptography library.
    """

    def __init__(self, alg: Union[RingAlgorithm, RustCryptoAlgorithm, SodiumoxideAlgorithm, OrionAlgorithm]) -> None:
        pass


class HPKEAlgorithm:
    """
    Enum representing supported algorithms for HPKE (Hybrid Public Key Encryption).

    Variants:
        - Aes128Gcm
        - Aes256Gcm (default)
        - ChaCha20Poly1305
    """
