//! Rendering bytes and text into the forms a wire protocol expects.
//!
//! Both helpers were copied per connector. `hex_encode` had drifted into three
//! spellings across eleven connectors — two building a `String` byte by byte
//! and one collecting through `format!` — which is three chances for one of
//! them to emit uppercase into a signature that is compared literally.

/// Percent-encode everything outside the RFC 3986 unreserved set.
///
/// Deliberately conservative. Over-encoding a path or a username is harmless;
/// under-encoding a client secret in a form body lets it introduce another
/// parameter, and under-encoding a password in a URI makes the client parse a
/// different host.
pub fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Lowercase hex, the spelling every signing scheme in this fleet compares
/// literally — AWS SigV4, SQL Server pre-login hashes, Oracle checksums.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encoding_covers_what_would_change_meaning() {
        assert_eq!(percent_encode("p@ss:word/1"), "p%40ss%3Aword%2F1");
        assert_eq!(percent_encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(percent_encode("plain-Token_1.0~"), "plain-Token_1.0~");
    }

    #[test]
    fn hex_is_lowercase_and_zero_padded() {
        // A signature compared byte-for-byte rejects "0A" where it wants "0a",
        // and drops a leading zero if the byte is formatted without padding.
        assert_eq!(hex_encode(&[0x00, 0x0a, 0xff]), "000aff");
        assert_eq!(hex_encode(b"irodori"), "69726f646f7269");
        assert_eq!(hex_encode(&[]), "");
    }
}
