use std::collections::HashMap;

use itertools::Itertools;
use rand::{Rng, OsRng};
use rustc_serialize::base64::*;

use utils::{bytes, crypto};

/// Encrypt the given data using 128-bit AES with a randomly generated key.
/// CBC mode will be used 50% of the time (with a randomly generated IV),
/// and ECB mode will be used otherwise. Returns the encrypted data along
/// with a boolean indicating that CBC mode was used.
pub fn encryption_oracle(data: &[u8]) -> (Vec<u8>, bool) {
    let mut rng = OsRng::new().unwrap();

    // Generate random AES key.
    let key = &mut [0u8; 16][..];
    rng.fill_bytes(key);

    // Add random prefix and suffix to data.
    let prefix_len = rng.gen_range(5usize, 10);
    let suffix_len = rng.gen_range(5usize, 10);
    let mut plaintext = Vec::with_capacity(prefix_len + data.len() + suffix_len);
    plaintext.extend(rng.gen_iter::<u8>().take(prefix_len));
    plaintext.extend(data);
    plaintext.extend(rng.gen_iter::<u8>().take(suffix_len));

    let cbc = rng.gen_weighted_bool(2);
    let result = if cbc {
        let iv = &mut [0u8; 16][..];
        rng.fill_bytes(iv);
        crypto::encrypt_cbc(key, iv, &plaintext)
    } else {
        crypto::encrypt_ecb(key, None, &plaintext, true)
    };

    (result, cbc)
}

/// Oracle struct that can be used to generate encrypted strings for challenge 12.
/// Contains a random key that is unknown to the attacker and fixed for the lifetime
/// of the oracle.
pub struct UnknownStringOracle {
    key: Vec<u8>,
}

/// The oracle accepts an array of bytes as input, appends a fixed, unknown [to the attacker]
/// string to it, and encrypts the result using AES-128-ECB using its fixed, unknown key.
impl UnknownStringOracle {
    pub fn new() -> Self {
        UnknownStringOracle { key: bytes::random(16) }
    }

    pub fn unknown_string() -> Vec<u8> {
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
         aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
         dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
         YnkK"
            .from_base64()
            .unwrap()
    }

    pub fn encrypt(&self, bytes: &[u8]) -> Vec<u8> {
        let mut plaintext = bytes.to_vec();
        plaintext.extend(Self::unknown_string());
        crypto::encrypt_ecb(&self.key, None, &plaintext, true)
    }
}



pub struct ProfileCookieOracle {
    key: Vec<u8>,
}


impl ProfileCookieOracle {
    pub fn new() -> Self {
        ProfileCookieOracle { key: bytes::random(16) }
    }

    /// Generate an encrypted profile cookie with the given email address.
    pub fn encrypt_cookie(&self, email: &str) -> Vec<u8> {
        let profile = bytes::from_string(&Self::profile_for(email));
        crypto::encrypt_ecb(&self.key, None, &profile, true)
    }

    /// Decrypt and parse the given byte string as a cookie.
    pub fn decrypt_cookie(&self, bytes: &[u8]) -> HashMap<String, String> {
        let profile = bytes::to_string(&crypto::decrypt_ecb(&self.key, None, bytes, true));
        Self::parse_cookie(&profile)
    }

    /// Parse a string of key-value pairs delimited by '&' and '=' into a HashMap.
    fn parse_cookie(string: &str) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for token in string.split('&') {
            let mut pair = token.split('=');
            if let Some(key) = pair.next() {
                let value = pair.next().unwrap_or("");
                map.insert(key.to_string(), value.to_string());
            }
        }
        map
    }

    /// Turn an iterable of key-value pairs into a cookie string.
    fn make_cookie<T>(pairs: T) -> String
        where T: IntoIterator<Item = (String, String)>
    {
        pairs.into_iter()
            .map(|(key, value)| {
                key.to_string() + "=" + &value
            })
            .intersperse("&".to_string())
            .collect::<Vec<_>>()
            .concat()
    }

    /// Generated profile cookies for a given email address, following a fixed format.
    fn profile_for(email: &str) -> String {
        // Use vector instead of map to maintain ordering.
        let mut pairs = Vec::new();
        let sanitized = email.replace("&", "").replace("=", "");
        pairs.push(("email".to_string(), sanitized));
        pairs.push(("uid".to_string(), "10".to_string()));
        pairs.push(("role".to_string(), "user".to_string()));
        Self::make_cookie(pairs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_cookie() {
        let oracle = ProfileCookieOracle::new();
        let cookie = oracle.encrypt_cookie("foo@bar.com&role=admin");
        let result = oracle.decrypt_cookie(&cookie);

        assert_eq!(result.get("uid"), Some(&"10".to_string()));
        assert_eq!(result.get("email"), Some(&"foo@bar.comroleadmin".to_string()));
        assert_eq!(result.get("role"), Some(&"user".to_string()));
    }
}
