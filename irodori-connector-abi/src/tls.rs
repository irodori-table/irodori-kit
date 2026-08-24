//! Reading the certificate material a profile points at.

/// Read a PEM file, naming both the field and the path when it cannot be read.
///
/// The message matters more than the two lines of code: a user who typed the
/// wrong path into `caCertificate` sees which field they got wrong, not a bare
/// `No such file or directory` from somewhere inside a TLS handshake.
pub fn read_pem(path: &str, label: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|err| format!("{label} at {path} could not be read: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unreadable_certificate_names_the_file_and_the_field() {
        let error = read_pem("/nonexistent/ca.pem", "caCertificate").unwrap_err();
        assert!(error.starts_with("caCertificate at /nonexistent/ca.pem could not be read: "));
    }

    #[test]
    fn a_readable_file_comes_back_verbatim() {
        let dir = std::env::temp_dir().join("irodori-abi-tls-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ca.pem");
        std::fs::write(&path, b"-----BEGIN CERTIFICATE-----\n").unwrap();
        assert_eq!(
            read_pem(path.to_str().unwrap(), "caCertificate").unwrap(),
            b"-----BEGIN CERTIFICATE-----\n".to_vec()
        );
        std::fs::remove_file(&path).unwrap();
    }
}
