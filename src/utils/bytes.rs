use std::collections::HashMap;
use std::ops::Range;
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
pub fn single_byte_brute_force(ciphertext: &[u8]) -> (f64, String, u8) {
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

    (best_score, result, key)
}

/// Compute the bitwise Hamming distance between two byte arrays.
pub fn hamming_dist(a: &[u8], b: &[u8]) -> u32 {
    a.iter().zip(b.iter()).map(|(x, y)| (x ^ y).count_ones()).sum()
}

/// Determine the most likely key sizes for a repeating-key XOR encoded ciphertext.
/// Returns a vector of potential key sizes, sorted in ascending order by the
/// mean normalized Hamming distance between chunks of that size in the ciphertext.
pub fn get_keysizes(ciphertext: &[u8], range: Range<usize>, limit: usize) -> Vec<usize> {
    let mut sizes = Vec::new();

    // Check key sizes in given size range.
    for size in range {
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

    // Floats are not (in general) totally ordered, so we need to use a partially ordered sort,
    // but assume that the actual values we get are totally ordered since we don't expect NaNs.
    sizes.sort_by(|&(a, _), &(b, _)| a.partial_cmp(&b).unwrap());
    sizes.into_iter().map(|(_, size)| size).take(limit).collect()
}

/// Transpose a collection of byte strings. Given M byte strings of length N, returns
/// N byte strings of length M, where the nth byte string contains the concatenation
/// of the nth byte of each of the input byte strings. Determines the length N from the
/// first byte string; subsequent byte strings can be longer or shorter, but at most
/// N byte strings will be produced. In the case of shorter input byte strings, some
/// of the output byte strings may be shorter than M. This length flexibility allows this
/// function to be used with iterators like Chunks<u8>, which may have a short last element.
pub fn transpose<'a, T>(input: T) -> Vec<Vec<u8>>
    where T: IntoIterator<Item = &'a [u8]>
{
    // Gather the input byte strings and determine the length of the first.
    let slices = input.into_iter().collect::<Vec<&[u8]>>();
    let n = slices.first()
       .map(|slice| slice.len())
       .unwrap_or(0);

     // Initialize empty vectors that will contain the transposed bytes.
    let mut transposed = (0..n)
        .map(|_| Vec::with_capacity(slices.len()))
        .collect::<Vec<Vec<u8>>>();

    // Convert the input byte strings into iterators that we will iterator over in lockstep.
    let mut slice_iters = slices.iter()
        .map(|slice| slice.iter())
        .collect::<Vec<_>>();

    // Insert the nth byte from each byte string into the nth vector of the output.
    for mut vector in &mut transposed {
        for mut iter in &mut slice_iters {
            if let Some(byte) = iter.next() {
                vector.push(*byte);
            }
        }
    }

    transposed
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

/// Convert an iterable of bytes to a printable string.
pub fn to_string<'a, T>(bytes: T) -> String
    where T: IntoIterator<Item = &'a u8>
{
    let vector = bytes.into_iter().cloned().collect::<Vec<u8>>();
    String::from_utf8_lossy(&vector).into_owned()
}

/// Pad the given iterable of bytes to the given length using PKCS#7 padding.
/// Padded length cannot be less than the original length, and can be at most
/// 255 bytes greater than the original length.
pub fn pad<'a, T>(bytes: T, length: usize) -> Vec<u8>
    where T: IntoIterator<Item = &'a u8>
{
    let vec = bytes.into_iter().cloned().collect::<Vec<u8>>();

    // Guard against underflow and truncation for the sake of security.
    match length.checked_sub(vec.len()) {
        Some(pad) if pad < 256 => {
            vec.into_iter()
                .chain(iter::repeat(pad as u8))
                .take(length)
                .collect()
        },
        Some(_) => panic!("Padding length exceeds 255 bytes."),
        None => panic!("Padded size less than original size."),
    }
}
