use utils::{bytes, crypto};

/// Implement PKCS#7 padding.
pub fn challenge_9() -> String {
    let input = &b"YELLOW SUBMARINE"[..];
    bytes::to_string(&crypto::pad_pkcs7(input, 20).unwrap())
}

pub fn challenge_10() -> String {
    String::new()
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
}
