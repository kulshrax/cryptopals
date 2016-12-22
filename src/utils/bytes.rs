use std::collections::HashMap;
use std::f64;
use std::iter;
use itertools::Itertools;
use utils::text::score_text;

/// XOR two byte strings, truncating the longer one if the sizes are different.
pub fn xor<'a, 'b, A, B>(a: A, b: B) -> Vec<u8>
    where A: IntoIterator<Item = &'a u8>,
          B: IntoIterator<Item = &'b u8>
{
    a.into_iter().zip(b.into_iter()).map(|(x, y)| *x ^ *y).collect()
}

/// Brute force an English string that has been XOR'd with a single byte.
pub fn single_byte_brute_force(ciphertext: &[u8]) -> (f64, u8, String) {
    let mut result = String::new();
    let mut best_score = f64::MIN;
    let mut key = 0u8;

    for byte in 0..255u8 {
        let decoded_bytes = xor(ciphertext, iter::repeat(&byte));
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
/// Returns a vector of potential key sizes, sorted in ascending order by the
/// mean normalized Hamming distance between chunks of that size in the ciphertext.
pub fn get_keysizes(ciphertext: &[u8]) -> Vec<usize> {
    let mut sizes = Vec::new();

    // Check key sizes 2 to 40 bytes.
    for size in 2..41 {
        // Maximum number of chunks to test. Overall space/time usage is varies factorially
        // with this parameter, so large values may cause this function to take a long time.
        let num_chunks = 4;

        // Get Hamming distances of pairs of chunks of the given size.
        let dists = ciphertext
            .chunks(size)
            .take(num_chunks)
            .combinations(2)
            .map(|pair| {
                hamming_dist(pair[0], pair[1]) as f64 / size as f64
            }).collect::<Vec<f64>>();

        let avg = dists.iter().sum::<f64>() / dists.len() as f64;
        sizes.push((avg, size));
    }

    // Floats are not totally ordered, so we need to use a partially ordered sort.
    sizes.sort_by(|&(a, _), &(b, _)| a.partial_cmp(&b).unwrap());
    sizes.into_iter().map(|(_, size)| size).collect()
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

// Transpose an iterable of byte strings into a vector of vectors of bytes.
// The nth vector will contain the nth byte of each string in order.
// pub fn transpose<T>(iter: T) -> Vec<Vec<u8>>
//     where T: IntoIterator<Item = &[u8]>
// {
//     let bytes = iter.collect();
//     let mut transposed = .map(|_| Vec::new()).collect::<Vec<Vec<u8>>>();
//     for chunk in ciphertext.chunks(*size) {
//         for (byte, vector) in chunk.iter().zip(transposed.iter_mut()) {
//             vector.push(*byte);
//         }
//     }
//     transposed
// }
