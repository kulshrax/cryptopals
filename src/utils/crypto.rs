use std::iter;
use openssl::symm::{Cipher, Crypter, Mode};
use rand::{Rng, OsRng};
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
    if let Some(pad) = bytes.last() {
        // Check if the last `pad` bytes all have a value equal to `pad`.
        if bytes.iter().rev().take(*pad as usize).all(|byte| *byte == *pad) {
            return Some(bytes[0 .. bytes.len() - *pad as usize].to_vec());
        }
    }
    None
}

// Clone of the openssl::symm::cipher() function, with the additional option to enable
// or disable padding of the output.
fn run_crypter(cipher: Cipher, mode: Mode, key: &[u8], iv: Option<&[u8]>, data: &[u8], pad: bool)
          -> Vec<u8> {
    let mut crypter = Crypter::new(cipher, mode, key, iv).unwrap();
    crypter.pad(pad);
    let mut output = vec![0; data.len() + cipher.block_size()];
    let count = crypter.update(data, &mut output).unwrap();
    let rest = crypter.finalize(&mut output[count..]).unwrap();
    output.truncate(count + rest);
    output
}

/// Encrypt the given data with AES-128-ECB encryption.
pub fn encrypt_ecb(key: &[u8], iv: Option<&[u8]>, data: &[u8], pad: bool) -> Vec<u8> {
    run_crypter(Cipher::aes_128_ecb(), Mode::Encrypt, key, iv, data, pad)
}

/// Decrypt data encrypted with AES-128-ECB encryption.
pub fn decrypt_ecb(key: &[u8], iv: Option<&[u8]>, data: &[u8], pad: bool) -> Vec<u8> {
    run_crypter(Cipher::aes_128_ecb(), Mode::Decrypt, key, iv, data, pad)
}

/// Basic implementation of a CBC-mode encryption, using OpenSSL's AES-128-ECB function
/// as the underlying block cipher.
pub fn encrypt_cbc(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    // Hardcode this to 16 bytes since we're using 128-bit AES.
    let block_size = 16;

    // Number of 128-bit blocks in the output. If the input length is a perfect multiple of
    // the block size, add an extra block due to PKCS#7 padding.
    let num_blocks = data.len() / block_size + 1;

    // Pad input to be a perfect multiple of the block size.
    let padded = pad_pkcs7(data, num_blocks * block_size).unwrap();

    // Output vector of encrypted blocks.
    let mut blocks: Vec<Vec<u8>> = Vec::with_capacity(num_blocks);

    // Break input into 128-bit blocks.
    for block in padded.chunks(block_size) {
        // XOR with previous ciphertext block (or IV for the first block).
        let chained = bytes::xor(block, blocks.last().unwrap_or(&iv.to_vec()));

        // Encrypt XOR'd block with AES-128-ECB. Each encrypted block will end up
        // being 256 bits long due to OpenSSL adding padding to each block.
        blocks.push(encrypt_ecb(key, None, &chained, false));
    }

    // Concatenate blocks into final ciphertext.
    blocks.into_iter().flat_map(|block| block.into_iter()).collect()
}

/// Decrypt data encrypted AES-128-CBC, as implemented by the encrypt_cbc function.
pub fn decrypt_cbc(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    // Cached ciphertext block for chaining.
    let mut last = None;

    // Decrypt 32 bytes at a time, due to OpenSSL adding padding to each block.
    let padded = data.chunks(16).flat_map(|block| {
        // Decrypt block level encryption.
        let decrypted = decrypt_ecb(key, None, block, false);

        // XOR against previous ciphertext block (or IV for the first block).
        let chained = bytes::xor(&decrypted, last.unwrap_or(iv));
        last = Some(block);
        chained.into_iter()
    }).collect::<Vec<u8>>();

    // Strip padding before returning data.
    strip_pkcs7(&padded).unwrap()
}

/// Encrypt the given data using 128-bit AES with a randomly generated key.
/// CBC mode will be used 50% of the time (with a randomly generated IV),
/// and ECB mode will be used otherwise.
pub fn encryption_oracle(data: &[u8]) -> Vec<u8> {
    let mut rng = OsRng::new().unwrap();

    // Generate random AES key.
    let key = &mut [0u8; 16][..];
    rng.fill_bytes(key);

    // Add random prefix and suffix to data.
    let prefix_len = rng.gen_range(5usize, 10);
    let suffix_len = rng.gen_range(5usize, 10);
    let mut plaintext = Vec::with_capacity(prefix_len + data.len() + suffix_len);
    plaintext.extend(rng.gen_iter::<u8>().take(prefix_len));
    plaintext.extend(data);
    plaintext.extend(rng.gen_iter::<u8>().take(suffix_len));

    if rng.gen_weighted_bool(2) {
        // CBC mode.
        let iv = &mut [0u8; 16][..];
        rng.fill_bytes(iv);
        return encrypt_cbc(key, iv, &plaintext);
    } else {
        // ECB mode.
        return encrypt_ecb(key, None, &plaintext, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbc() {
        let input = &b"The quick brown fox jumps over the lazy dog."[..];
        let key = &b"YELLOW SUBMARINE"[..];
        let iv =  &b"abcdefghijklmnop"[..];
        let encrypted = encrypt_cbc(key, iv, input);
        let decrypted = decrypt_cbc(key, iv, &encrypted);
        assert_eq!(input, &decrypted[..]);
    }
}
