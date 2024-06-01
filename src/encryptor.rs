use std::io;

trait Encryptor {
    fn encrypt<'a>(plaintext: &'a mut [u8], block_index: Option<u64>, aad: Option<&[u8]>, nonce: Option<&[u8]>,
                   tag_out: &mut [u8], nonce_out: &mut [u8]) -> io::Result<&'a [u8]>;

    fn decrypt<'a>(ciphertext_and_tag: &'a mut [u8], block_index: Option<u64>, aad: Option<&[u8]>, nonce: &[u8]) -> io::Result<&'a mut [u8]>;
}