use rustc_serialize::base64::*;
use utils::{attacks, bytes, crypto};

/// Implement PKCS#7 padding.
pub fn challenge_9() -> String {
    let input = &b"YELLOW SUBMARINE"[..];
    bytes::to_string(&crypto::pad_pkcs7(input, 20).unwrap())
}

/// Implement CBC mode.
pub fn challenge_10() -> String {
    let input = include_str!("data/10.txt").to_string().replace("\n", "");
    let ciphertext = input.from_base64().unwrap();

    let key = &b"YELLOW SUBMARINE"[..];
    let iv = [0u8; 16];

    let decrypted = crypto::decrypt_cbc(key, &iv, &ciphertext);
    bytes::to_string(&decrypted)
}

/// An ECB/CBC detection oracle.
pub fn challenge_11() -> bool {
    let data = [0u8; 64];
    let (encrypted, cbc) = crypto::encryption_oracle(&data);
    attacks::detect_ecb(&encrypted, 16) != cbc
}

/// Byte-at-a-time ECB decryption (Simple).
pub fn challenge_12() -> String {
    // Initialize the oracle and wrap it in a closure so it can be easily passed around.
    let oracle = crypto::UnknownStringOracle::new();
    let mut encrypt = |bytes: &[u8]| -> Vec<u8> { oracle.encrypt(bytes) };

    // Detect block size.
    let block_size = attacks::detect_block_size(&mut encrypt).unwrap();

    // We know that the block size is actually 128 bits.
    assert_eq!(block_size, 16);

    // Multiply block size by 4 to ensure that even if an arbitrary amount of random
    // padding is preprended by the oracle, we will still have two full blocks of zeros.
    let zeros = vec![0u8; block_size * 4];
    let encrypted_zeros = encrypt(&zeros);

    // Detect that ECB is being used. We know that this is the case.
    assert!(attacks::detect_ecb(&encrypted_zeros, block_size));

    // Decrypt the unknown string.
    attacks::decrypt_ecb_suffix(&mut encrypt, block_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_9() {
        let result = challenge_9();
        let expected = "YELLOW SUBMARINE\x04\x04\x04\x04";
        assert_eq!(result, expected);
    }

    #[test]
    fn text_challenge_10() {
        let result = challenge_10();
        let expected = include_str!("data/play_that_funky_music.txt");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_challenge_11() {
        // Since encryption oracle output is non-deterministic, do several trials to be sure.
        for _ in 0..30 {
            assert!(challenge_11());
        }
    }

    #[test]
    fn test_challenge_12() {
        let result = challenge_12();
        let expected = "hola";
        assert_eq!(result, expected);
    }
}
