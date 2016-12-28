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
        let dists = ciphertext.chunks(size)
            .take(num_chunks)
            .combinations(2)
            .map(|pair| bytes::hamming_dist(pair[0], pair[1]) as f64 / size as f64)
            .collect::<Vec<f64>>();

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
pub fn max_repeated_blocks(bytes: &[u8], block_size: usize) -> i32 {
    let mut counts = HashMap::new();

    for chunk in bytes.chunks(block_size) {
        let count = counts.entry(chunk).or_insert(0i32);
        *count += 1;
    }

    counts.values().cloned().max().unwrap_or(0)
}

/// Given a ciphertext and a block size, returns true if the ciphertext appears to be
/// encrypted using ECB mode. This is just a simple heuristic that looks for repeated
/// blocks, and as such doesn't guarantee that ECB mode was used. The check will
/// fail if the plaintext didn't have any repeated blocks to begin with.
pub fn detect_ecb(bytes: &[u8], block_size: usize) -> bool {
    max_repeated_blocks(bytes, block_size) > 1
}

/// Given a block cipher encryption function, detect the block size of the cipher.
pub fn detect_block_size<F>(encrypt: &mut F) -> Option<usize>
    where F: FnMut(&[u8]) -> Vec<u8>
{
    let mut input = vec![0u8];
    let mut encrypted = encrypt(&input);

    // Find an input size such that the prefix of the ciphertext remains fixed. This indicates
    // that we've filled the first block on the previous iteration.
    for i in 1..40 {
        let old = encrypted;
        input.push(0);
        encrypted = encrypt(&input);
        if encrypted[0..i] == old[0..i] {
            return Some(i);
        }
    }

    None
}

/// Given an ECB encryption function with known block size that appends an unknown suffix
/// to its input prior to encryption, use knowledge of the block size and brute force to
/// decrypt the suffix one byte at a time without knowlege of the key.
pub fn decrypt_ecb_suffix<F>(encrypt: &mut F, block_size: usize) -> String
    where F: FnMut(&[u8]) -> Vec<u8>
{
    let mut decrypted = Vec::new();

    for i in 1..block_size {
        let mut pad = vec![0u8; block_size - i];
        let encrypted = encrypt(&pad);
        pad.extend(&decrypted);

        // Try all possibilities for the last byte in the first block.
        for byte in 0..255u8 {
            pad.push(byte);
            let test = encrypt(&pad);
            if test[0..block_size] == encrypted[0..block_size] {
                // Found matching byte!
                decrypted.push(byte);
                break;
            }
            pad.pop();
        }
    }

    bytes::to_string(&decrypted)
}
