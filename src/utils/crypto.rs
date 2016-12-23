use std::iter;
use openssl::symm::{Cipher, encrypt, decrypt};
use utils::bytes;

/// Pad the given bytes array to the given length using PKCS#7 padding.
/// Padded length cannot be less than the original length, and can be at most
/// 255 bytes greater than the original length.
pub fn pad_pkcs7(bytes: &[u8], length: usize) -> Result<Vec<u8>, &'static str> {
    match length.checked_sub(bytes.len()) {
        Some(pad) if pad < 256 => {
            Ok(bytes.iter()
                .cloned()
                .chain(iter::repeat(pad as u8))
                .take(length)
                .collect()
            )
        },
        Some(_) => Err("Padding length exceeds 255 bytes."),
        None => Err("Padded size less than original size."),
    }
}

/// Remove PKCS#7 padding from the given byte array.
/// Returns None if the padding is invalid.
pub fn strip_pkcs7(bytes: &[u8]) -> Option<Vec<u8>>
{
    None
}

/// Basic implementation of a CBC-mode encryption, using OpenSSL's AES-128-ECB function
/// as the underlying block cipher. The input plaintext can be arbirarily sized and
/// will be padded to a multiple of 128 bytes with PKCS#7 padding. The key and IV
/// must be 16 bytes (128 bits).
pub fn encrypt_cbc(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    let mut blocks: Vec<Vec<u8>> = Vec::with_capacity((data.len() - 1) / 16 + 1);

    // Break input into 128-bit blocks.
    for block in data.chunks(16) {
        // XOR with previous ciphertext block (or IV for the first block).
        let chained = bytes::xor(block, blocks.last().unwrap_or(&iv.to_vec()));

        // Encrypt XOR'd block with AES-128-ECB.
        blocks.push(encrypt(Cipher::aes_128_ecb(), key, None, &chained).unwrap());
    }

    // Concatenate blocks into final ciphertext.
    blocks.into_iter().flat_map(|block| block.into_iter()).collect()
}

pub fn decrypt_cbc(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    // Cached ciphertext block for chaining.
    let mut last = None;

    data.chunks(16).flat_map(|block| {
        // Decrypt block level encryption.
        let decrypted = decrypt(Cipher::aes_128_ecb(), key, None, block).unwrap();

        // XOR against previous ciphertext block (or IV for the first block).
        let chained = bytes::xor(&decrypted, last.unwrap_or(iv));
        last = Some(block);
        chained.into_iter()
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbc() {
        let input = &b"ABCDEFGHIJKLMNOP"[..];
        let key = &b"YELLOW SUBMARINE"[..];
        let iv =  &b"abcdefghijklmnop"[..];
        let encrypted = encrypt_cbc(key, iv, input);
        let decrypted = decrypt_cbc(key, iv, &encrypted);
        assert_eq!(input, &decrypted[..]);
    }
}
