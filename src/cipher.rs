use std::io;

trait Cipher {
    fn seal_in_place<'a>(plaintext: &'a mut [u8], block_index: Option<u64>, aad: Option<&[u8]>, nonce: Option<&[u8]>,
                         tag_out: &mut [u8], nonce_out: Option<&mut [u8]>) -> io::Result<&'a [u8]>;

    fn open_in_place<'a>(ciphertext_and_tag: &'a mut [u8], block_index: Option<u64>, aad: Option<&[u8]>, nonce: &[u8]) -> io::Result<&'a mut [u8]>;
}