use rustc_serialize::base64::*;
use rustc_serialize::hex::*;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_1() {
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let result = challenge_1();
        assert_eq!(result, expected);
    }
}
