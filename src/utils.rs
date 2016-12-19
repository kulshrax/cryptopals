/// The alphabet stored as a static array for ease of access.
static ALPHABET: [char; 26] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
];

/// Letter frequencies in the English language, based on the Oxford English Dictionary.
/// Values obtained from https://en.wikipedia.org/wiki/Letter_frequency.
static LETTER_FREQS: [f64; 26] = [
    0.08167, // A
    0.01492, // B
    0.02782, // C
    0.04253, // D
    0.12702, // E
    0.02228, // F
    0.02015, // G
    0.06094, // H
    0.06966, // I
    0.00153, // J
    0.00772, // K
    0.04025, // L
    0.02406, // M
    0.06749, // N
    0.07507, // O
    0.01929, // P
    0.00095, // Q
    0.05987, // R
    0.06327, // S
    0.09056, // T
    0.02758, // U
    0.00978, // V
    0.02360, // W
    0.00150, // X
    0.01974, // Y
    0.00074, // Z
];

/// Compute L2 (Euclidean) distance between two vectors.
fn l2_distance(u: &[f64], v: &[f64]) -> f64 {
    u.iter().zip(v.iter()).map(|(x, y)| (x - y).powi(2)).sum()
}

/// Find the position of the given character in the English alphabet.
/// Return None if the character is not part of the alphabet.
fn alphabet_position(c: char) -> Option<usize> {
    let mut iter = c.to_lowercase();

    // Ensure that this character converts to exactly 1 lowercase character.
    if let Some(lower) = iter.next() {
        if let None = iter.next() {
            return ALPHABET.iter().position(|&x| x == lower);
        }
    }
    None
}

/// Score a text based on similarity to known English letter frequencies.
pub fn score_text(text: &str) -> f64 {
    let mut counts = [0.0f64; 26];
    let mut total = 0.0f64;

    // Count the occurrence of letters in the input text.
    for c in text.chars() {
        if let Some(i) = alphabet_position(c) {
            let count = &mut counts[i];
            *count += 1.0;
            total += 1.0;
        }
    }

    // Normalize by total number of characters (not just total number of letters).
    //let total = text.chars().count() as f64;
    for count in &mut counts {
        *count = *count / total;
    }

    1.0 - l2_distance(&LETTER_FREQS, &counts)
}

/// XOR two byte strings, truncating the longer one if the sizes are different.
pub fn xor<'a, 'b, A, B>(a: A, b: B) -> Vec<u8>
    where A: IntoIterator<Item = &'a u8>,
          B: IntoIterator<Item = &'b u8>
{
    a.into_iter().zip(b.into_iter()).map(|(x, y)| *x ^ *y).collect()
}
