use rustc_serialize::base64::*;
use utils::{bytes, crypto};

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
    false
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
        assert!(challenge_11());
    }
}
