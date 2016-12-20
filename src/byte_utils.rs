use std::f64;
use std::iter;
use rustc_serialize::hex::*;
use text_utils::score_text;

/// XOR two byte strings, truncating the longer one if the sizes are different.
pub fn xor<'a, 'b, A, B>(a: A, b: B) -> Vec<u8>
    where A: IntoIterator<Item = &'a u8>,
          B: IntoIterator<Item = &'b u8>
{
    a.into_iter().zip(b.into_iter()).map(|(x, y)| *x ^ *y).collect()
}

/// Brute force an English string that has been XOR'd with a single byte.
pub fn single_byte_brute_force(input: &str) -> (f64, String) {
    let input_bytes = input.from_hex().unwrap();

    let mut result = String::new();
    let mut best_score = f64::MIN;

    for byte in 0..255u8 {
        let decoded_bytes = xor(&input_bytes, iter::repeat(&byte));
        if let Ok(decoded) = String::from_utf8(decoded_bytes) {
            let score = score_text(&decoded);
            if score > best_score {
                best_score = score;
                result = decoded;
            }
        }
    }

    (best_score, result)
}
