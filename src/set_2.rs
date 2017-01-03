use std::collections::HashMap;

use rustc_serialize::base64::*;

use utils::{attacks, bytes, crypto, oracles};

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
    let (encrypted, cbc) = oracles::encryption_oracle(&data);
    attacks::detect_ecb(&encrypted, 16) != cbc
}

/// Byte-at-a-time ECB decryption (Simple).
pub fn challenge_12() -> String {
    // Initialize the oracle and wrap it in a closure so it can be easily passed around.
    let oracle = oracles::UnknownStringOracle::new(false);
    let mut encrypt = |bytes: &[u8]| -> Vec<u8> { oracle.encrypt(bytes) };

    // Detect block size.
    let block_size = attacks::detect_block_size(&mut encrypt).unwrap();

    // We know that the block size is actually 128 bits.
    assert_eq!(block_size, 16);

    // Multiply block size by 4 to ensure that even if an arbitrary amount of random
    // padding is preprended by the oracle, we will still have two full blocks of zeros.
    let zeros = vec![0u8; block_size * 4];
    let encrypted_zeros = encrypt(&zeros);

    // Determine how many additional blocks of suffix are being added to the input.
    let num_blocks = encrypted_zeros.len() / block_size - 4;

    // Detect that ECB is being used. We know that this is the case.
    assert!(attacks::detect_ecb(&encrypted_zeros, block_size));

    // Decrypt the unknown string.
    attacks::decrypt_ecb_suffix(&mut encrypt, block_size, num_blocks)
}

/// ECB cut-and-paste.
pub fn challenge_13() -> HashMap<String, String> {

    // Each block of the ciphertext is encrypted independently with the same key, so we can
    // rearrange blocks arbitrarily. If we create an email whose length forces "user" to be
    // at the start of a new block, and create an intermediate block with "admin" at the
    // start of it (followed by the appropriate PKCS#7 padding, since the "user" block is at
    // the end of the ciphertext), we can replace the last block of the ciphertext with that
    // block. See the diagram below. The B's after "admin" should be replaced with valid
    // padding bytes, namely the value 11 (0x0B) repeated 11 times.
    //
    // |email=..........|adminBBBBBBBBBBB|...&uid=10&role=|userCCCCCCCCCCCC|
    // |0123456789ABCDEF|0123456789ABCDEF|0123456789ABCDEF|0123456789ABCDEF|

    let oracle = oracles::ProfileCookieOracle::new();
    let email = "..........admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b...";
    let cookie = oracle.encrypt_cookie(email);
    let mut tampered = Vec::new();
    tampered.extend(&cookie[0..48]);
    tampered.extend(&cookie[16..32]);
    oracle.decrypt_cookie(&tampered)
}

/// Byte-at-a-time ECB decryption (Harder).
pub fn challenge_14() {

}

/// PKCS#7 padding validation.
pub fn challenge_15() -> (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>) {
    (
        crypto::strip_pkcs7(&b"ICE ICE BABY\x04\x04\x04\x04"[..]),
        crypto::strip_pkcs7(&b"ICE ICE BABY\x05\x05\x05\x05"[..]),
        crypto::strip_pkcs7(&b"ICE ICE BABY\x01\x02\x03\x04"[..]),
    )
}

/// CBC bitflipping attacks.
pub fn challenge_16() -> String {

    // ';' has ASCII code 59 and '=' has ASCII code 61. By replacing them with
    // ':' (ASCII code 58) and '<' (ASCII code 60), we can make CBC decryption
    // transform those bytes into the correct characters by flipping the lowest order
    // bits of the corresponding bytes in the previous block of ciphertext.
    //
    // |comment1=cooking|%20MCs;userdata=|................|:admin<true:....|
    // |0123456789ABCDEF|0123456789ABCDEF|0123456789ABCDEF|0123456789ABCDEF|

    let oracle = oracles::CBCCookieOracle::new();
    let userdata = "................:admin<true:....";
    let mut ciphertext = oracle.encrypt(userdata);

    ciphertext[32] ^= 1;
    ciphertext[38] ^= 1;
    ciphertext[43] ^= 1;

    oracle.decrypt(&ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::{bytes, oracles};

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
        let expected = bytes::to_string(&oracles::UnknownStringOracle::unknown_string());
        let result = challenge_12();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_challenge_13() {
        let result = challenge_13();
        assert_eq!(result.get("role").unwrap(), "admin");
    }

    #[test]
    fn test_challenge_14() {

    }

    #[test]
    fn test_challenge_15() {
        let result = challenge_15();
        let expected = (Some(b"ICE ICE BABY"[..].to_vec()), None, None);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_challenge_16() {
        let result = challenge_16();
        assert!(result.contains(";admin=true;"));
    }
}
