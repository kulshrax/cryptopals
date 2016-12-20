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
pub fn single_byte_brute_force(input: &str) -> (f64, u8, String) {
    let input_bytes = input.from_hex().unwrap();

    let mut result = String::new();
    let mut best_score = f64::MIN;
    let mut key = 0u8;

    for byte in 0..255u8 {
        let decoded_bytes = xor(&input_bytes, iter::repeat(&byte));
        if let Ok(decoded) = String::from_utf8(decoded_bytes) {
            let score = score_text(&decoded);
            if score > best_score {
                best_score = score;
                result = decoded;
                key = byte
            }
        }
    }

    (best_score, key, result)
}

/// Compute the bitwise Hamming distance between two byte arrays.
pub fn hamming_dist(a: &[u8], b: &[u8]) -> u32 {
    a.iter().zip(b.iter()).map(|(x, y)| (x ^ y).count_ones()).sum()
}

/// Determine the most likely key sizes for a repeating-key XOR encoded ciphertext.
/// Return the potential sizes in order of likelihood.
fn get_keysizes(ciphertext: &[u8]) -> Vec<usize> {
    let mut sizes = Vec::new();

    for size in 2..40usize {
        let one = &ciphertext[0 .. size];
        let two = &ciphertext[size .. size * 2];
        let dist = hamming_dist(one, two) as f64 / size as f64;
        sizes.push((dist, size));
    }

    sizes.sort_by(|&(a, _), &(b, _)| a.partial_cmp(&b).unwrap());
    sizes.into_iter().map(|(_, size)| size).collect()
}
