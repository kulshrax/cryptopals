use std::collections::HashMap;
use std::ops::Range;
use std::f64;
use std::iter;

use itertools::Itertools;

use utils::{bytes, text};

/// Brute force an English string that has been XOR'd with a single byte.
pub fn single_byte_brute_force(ciphertext: &[u8]) -> (f64, String, u8) {
    let mut result = String::new();
    let mut best_score = f64::MIN;
    let mut key = 0u8;

    for byte in 0..255u8 {
        let decoded_bytes = bytes::xor(ciphertext, iter::repeat(&byte));
        if let Ok(decoded) = String::from_utf8(decoded_bytes) {
            let score = text::score(&decoded);
            if score > best_score {
                best_score = score;
                result = decoded;
                key = byte
            }
        }
    }

    (best_score, result, key)
}

/// Determine the most likely key sizes for a repeating-key XOR encoded ciphertext.
/// Returns a vector of potential key sizes, sorted in ascending order by the
/// mean normalized Hamming distance between chunks of that size in the ciphertext.
pub fn get_keysizes(ciphertext: &[u8], range: Range<usize>, limit: usize) -> Vec<usize> {
    let mut sizes = Vec::new();

    // Check key sizes in given size range.
    for size in range {
        // Maximum number of chunks to test. Overall space/time usage varies factorially
        // with this parameter, so large values may cause this function to take a long time.
        let num_chunks = 4;

        // Get Hamming distances of pairs of chunks of the given size.
        let dists = ciphertext
            .chunks(size)
            .take(num_chunks)
            .combinations(2)
            .map(|pair| {
                bytes::hamming_dist(pair[0], pair[1]) as f64 / size as f64
            }).collect::<Vec<f64>>();

        let avg = dists.iter().sum::<f64>() / dists.len() as f64;
        sizes.push((avg, size));
    }

    // Floats are not (in general) totally ordered, so we need to use a partially ordered sort,
    // but assume that the actual values we get are totally ordered since we don't expect NaNs.
    sizes.sort_by(|&(a, _), &(b, _)| a.partial_cmp(&b).unwrap());
    sizes.into_iter().map(|(_, size)| size).take(limit).collect()
}

/// Attempt to detect the use of an ECB mode block cipher by looking for repeated blocks
/// in the given byte string. Returns the maximum number of repetitions found for any block.
pub fn detect_ecb(bytes: &[u8], block_size: usize) -> i32 {
    let mut counts = HashMap::new();

    for chunk in bytes.chunks(block_size) {
        let count = counts.entry(chunk).or_insert(0i32);
        *count += 1;
    }

    counts.values().cloned().max().unwrap_or(0)
}

/// Given a ECB/CBC encryption oracle function, detect whether ECB or CBC mode was used
/// by mounting a chosen-plaintext attack. Returns the detection success rate as a float
/// for the given number of trials.
pub fn cbc_ebc_oracle(encrypter: &Fn(&[u8]) -> (Vec<u8>, bool), trials: Option<u32>) -> f64 {
    let mut total = 0;
    let mut success = 0;
    for _ in 0..trials.unwrap_or(1) {

    }
    success as f64 / total as f64
}
