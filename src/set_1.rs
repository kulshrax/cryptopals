use rustc_serialize::base64::*;
use rustc_serialize::hex::*;

use utils::*;

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

pub fn challenge_2() -> String {
    let a = "1c0111001f010100061a024b53535009181c".from_hex().unwrap();
    let b = "686974207468652062756c6c277320657965".from_hex().unwrap();
    xor_bytes(&a, &b).to_hex()
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
