use std::iter;

use rustc_serialize::base64::*;
use rustc_serialize::hex::*;

use utils::*;

/// Convert hex to base64.
pub fn challenge_1() -> String {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c\
                 696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let config = Config {
        char_set: CharacterSet::Standard,
        newline: Newline::LF,
        pad: false,
        line_length: None
    };
    input.from_hex().unwrap().to_base64(config)
}

/// Fixed XOR.
pub fn challenge_2() -> String {
    let a = "1c0111001f010100061a024b53535009181c".from_hex().unwrap();
    let b = "686974207468652062756c6c277320657965".from_hex().unwrap();
    xor(&a, &b).to_hex()
}

/// Single-byte XOR cipher.
pub fn challenge_3() -> String {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let input_bytes = input.from_hex().unwrap();

    let mut result = "".to_string();
    let mut best_score = 0.0f64;
    for byte in 0..255u8 {
        let decoded_bytes = xor(&input_bytes, iter::repeat(&byte));
        let decoded = String::from_utf8(decoded_bytes).unwrap();
        let score = score_text(&decoded);

        if score > best_score {
            best_score = score;
            result = decoded;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_1() {
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let result = challenge_1();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_challenge_2() {
        let expected = "746865206b696420646f6e277420706c6179";
        let result = challenge_2();
        assert_eq!(result, expected);
    }
}
