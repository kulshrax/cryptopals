use utils::bytes::*;

/// Implement PKCS#7 padding
pub fn challenge_9() -> String {
    let input = &b"YELLOW SUBMARINE"[..];
    to_string(&pad(input, 13))
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
