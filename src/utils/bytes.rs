use rand::{Rng, OsRng};

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
