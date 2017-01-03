use std::collections::HashMap;
use std::iter::{self, FromIterator};

use rand::{Rng, OsRng};

static BASE64_CHARS: &'static str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// XOR two byte strings, truncating the longer one if the sizes are different.
pub fn xor<'a, 'b, A, B>(a: A, b: B) -> Vec<u8>
    where A: IntoIterator<Item = &'a u8>,
          B: IntoIterator<Item = &'b u8>
{
    a.into_iter().zip(b.into_iter()).map(|(x, y)| *x ^ *y).collect()
}

/// Convert an iterable of bytes to a printable string.
pub fn to_string<'a, T>(bytes: T) -> String
    where T: IntoIterator<Item = &'a u8>
{
    let vector = bytes.into_iter().cloned().collect::<Vec<u8>>();
    String::from_utf8_lossy(&vector).into_owned()
}

/// Convert a string consisting of only ASCII characters into bytes.
/// All codepoints must fit into a u8. Does not handle UTF-8.
pub fn from_string(string: &str) -> Vec<u8> {
    string.chars().map(|c| c as u8).collect()
}

/// Convert a hexadecimal string to a vector of bytes.
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let chars = hex.chars().collect::<Vec<char>>();
    chars.chunks(2).map(|chunk| {
        let byte = chunk.iter().cloned().collect::<String>();
        u8::from_str_radix(&byte, 16).unwrap()
    }).collect()
}

/// Convert an array of bytes into a hexadecimal string.
pub fn hex_from_bytes(bytes: &[u8]) -> String {
    let hex_bytes = bytes.iter()
        .map(|b| format!("{:2x}", b))
        .collect::<Vec<String>>();
    hex_bytes.concat()
}

/// Convert a base64 string into a vector of bytes.
pub fn base64_to_bytes(base64: &str) -> Vec<u8> {
    // Build mapping from base64 characters to their indices in the string.
    let codes : HashMap<char, u32> = HashMap::from_iter(
        BASE64_CHARS.chars().enumerate().map(|(i, c)| (c, i as u32))
    );

    // Iterate over base64 string 4 chars at a time.
    let chars = base64.chars().collect::<Vec<char>>();
    chars.chunks(4).flat_map(|chunk| {
        // Strip padding.
        let stripped = chunk.iter().filter(|c| **c != '=').collect::<Vec<_>>();

        // Insert the bits corresponding to the indices of the given characters
        // into the lower 24 bits of a u32.
        let mut bits = 0;
        for i in 0..stripped.len() {
            bits |= (codes[&chunk[i]]) << ((3 - i) * 6);
        }

        // Decode 8 bits at a time.
        (0..(stripped.len() - 1)).map(|i| {
            let shift = (2 - i) * 8;
            ((bits & (0xFF << shift)) >> shift) as u8
        }).collect::<Vec<u8>>()
    }).collect()
}

/// Convert an array of bytes into a base64 string.
pub fn base64_from_bytes(bytes: &[u8]) -> String {
    let codes = BASE64_CHARS.chars().collect::<Vec<char>>();

    // Iterate over input 3 bytes at a time.
    bytes.chunks(3).map(|chunk| {
        // Insert bytes into the lower 24 bits of a u32.
        let mut bits = 0;
        for i in 0..chunk.len() {
            bits |= (chunk[i] as u32) << ((2 - i) * 8);
        }

        // Encode 6 bits at a time.
        let chars = (0..(chunk.len() + 1)).map(|i| {
            let shift = (3 - i) * 6;
            let index = ((bits & (0x3F << shift)) >> shift) as usize;
            codes[index]
        }).collect::<String>();

        // Append padding if there were fewer than 3 bytes.
        let padding = iter::repeat("=").take(3 - chunk.len()).collect::<String>();
        chars + &padding
    }).collect::<Vec<String>>().concat()
}

/// Convert a hexadecimal string into a base64 string.
pub fn hex_to_base64(hex: &str) -> String {
    base64_from_bytes(&hex_to_bytes(&hex))
}

/// Convert a base64 string into a hexadecimal string.
pub fn base64_to_hex(base64: &str) -> String {
    hex_from_bytes(&base64_to_bytes(&base64))
}

/// Compute the bitwise Hamming distance between two byte arrays.
pub fn hamming_dist(a: &[u8], b: &[u8]) -> u32 {
    a.iter().zip(b.iter()).map(|(x, y)| (x ^ y).count_ones()).sum()
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

/// Convenience function to generate a vector of random bytes.
pub fn random(size: usize) -> Vec<u8> {
    let mut rng = OsRng::new().unwrap();
    rng.gen_iter().take(size).collect()
}
