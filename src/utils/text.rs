use utils::math::cosine_sim;

/// The alphabet stored as a static array for ease of access.
static ALPHABET: [char; 26] = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
                               'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];

/// Letter frequencies in the English language, based on the Oxford English Dictionary.
/// Values obtained from https://en.wikipedia.org/wiki/Letter_frequency.
static LETTER_FREQS: [f64; 26] =
    [0.08167 /* A */, 0.01492 /* B */, 0.02782 /* C */, 0.04253 /* D */,
     0.12702 /* E */, 0.02228 /* F */, 0.02015 /* G */, 0.06094 /* H */,
     0.06966 /* I */, 0.00153 /* J */, 0.00772 /* K */, 0.04025 /* L */,
     0.02406 /* M */, 0.06749 /* N */, 0.07507 /* O */, 0.01929 /* P */,
     0.00095 /* Q */, 0.05987 /* R */, 0.06327 /* S */, 0.09056 /* T */,
     0.02758 /* U */, 0.00978 /* V */, 0.02360 /* W */, 0.00150 /* X */,
     0.01974 /* Y */, 0.00074 /* Z */];

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
    let mut space = false;

    // Count the occurrence of letters in the input text.
    for c in text.chars() {
        if c == ' ' {
            space = true;
        } else if let Some(i) = alphabet_position(c) {
            *(&mut counts[i]) += 1.0;
        }
    }

    // Crude heuristic: if there are no spaces, this probably isn't English text.
    // We need this because we don't have non-alphabetic character frequencies, but
    // we get incorrect results if we just ignore whitespace entirely.
    if !space {
        return 0.0;
    }

    // Compute similarity against known English letter frequencies.
    // No need to normalize the counts because cosine similarity takes care of this.
    cosine_sim(&LETTER_FREQS, &counts)
}
