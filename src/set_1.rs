use std::f64;
use rustc_serialize::base64::*;
use rustc_serialize::hex::*;
use openssl::symm::{Cipher, decrypt};
use byte_utils::*;
use std::fs::File;
use std::io::prelude::*;

/// Convert hex to base64.
pub fn challenge_1() -> String {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c\
                 696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let config = Config {
        char_set: CharacterSet::Standard,
        newline: Newline::LF,
        pad: false,
        line_length: None,
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
    let (_, _, result) = single_byte_brute_force(input);
    result
}

/// Detect single-character XOR.
pub fn challenge_4() -> String {
    let input = include_str!("data/4.txt");

    let mut result = String::new();
    let mut best_score = f64::MIN;

    for line in input.lines() {
        let (score, _, decoded) = single_byte_brute_force(line);
        if score > best_score {
            best_score = score;
            result = decoded;
        }
    }

    result
}

/// Implement repeating-key XOR.
pub fn challenge_5() -> String {
    let pad = b"ICE".iter().cycle();
    let text = &b"Burning 'em, if you ain't quick and nimble\n\
                  I go crazy when I hear a cymbal"[..];
    xor(text, pad).to_hex()
}

/// Break repeating-key XOR.
pub fn challenge_6() -> String {
    let input = include_str!("data/6.txt").to_string().replace("\n", "");
    let ciphertext = input.from_base64().unwrap();
    String::new()
}

// AES in ECB mode.
pub fn challenge_7() -> String {
    let input = include_str!("data/7.txt").to_string().replace("\n", "");
    let ciphertext = input.from_base64().unwrap();
    let cipher = Cipher::aes_128_ecb();
    let key = &b"YELLOW SUBMARINE"[..];
    let plaintext = decrypt(cipher, key, None, &ciphertext).unwrap();
    let mut f = File::create("foo.txt").unwrap();
    f.write(&plaintext);
    String::from_utf8_lossy(&plaintext).into_owned()
}

// Detect AES in ECB mode.
pub fn challenge_8() -> String {
    String::new()
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

    #[test]
    fn test_challenge_3() {
        let expected = "Cooking MC's like a pound of bacon";
        let result = challenge_3();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_challenge_4() {
        let expected = "Now that the party is jumping\n";
        let result = challenge_4();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_challenge_5() {
        let result = challenge_5();
        let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c\
                        2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b\
                        2027630c692b20283165286326302e27282f";
        assert_eq!(result, expected);
    }

    #[test]
    fn test_challenge_6() {
        let result = challenge_6();
        let expected = "";
        assert_eq!(result, expected);
    }

    #[test]
    fn test_challenge_7() {
        let result = challenge_7();
        let expected = include_str!("data/7_decrypted.txt");
        assert_eq!(result, expected);
    }

    #[test]
    fn text_challenge_8() {
        let result = challenge_7();
        let expected = "";
        assert_eq!(result, expected);
    }
}
