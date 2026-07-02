//! Secret handle and secure storage abstractions for connection credentials.

use std::collections::HashMap;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::{Command, Stdio};
use std::sync::Mutex;

use irodori_core::{IrodoriError, Result, SecretRef};

pub const CRATE_NAME: &str = "irodori-secure-store";
pub const DEFAULT_SERVICE: &str = "irodori-table";
#[cfg(target_os = "windows")]
const WINDOWS_MAX_CREDENTIAL_BLOB_SIZE: usize = 5 * 512;

pub trait SecureStore: Send + Sync {
    fn put(&self, handle: &SecretRef, value: SecretValue<'_>) -> Result<()>;
    fn get(&self, handle: &SecretRef) -> Result<Option<String>>;
    fn delete(&self, handle: &SecretRef) -> Result<()>;

    fn put_connection_secret(
        &self,
        connection_id: &str,
        purpose: SecretPurpose,
        value: SecretValue<'_>,
    ) -> Result<SecretRef> {
        let handle = connection_secret_ref(connection_id, purpose)?;
        self.put(&handle, value)?;
        Ok(handle)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretValue<'a>(&'a str);

impl<'a> SecretValue<'a> {
    pub fn new(value: &'a str) -> Result<Self> {
        if value.is_empty() {
            return Err(IrodoriError::validation("secret value cannot be empty"));
        }
        Ok(Self(value))
    }

    fn as_str(self) -> &'a str {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretPurpose {
    Password,
    Token,
    PrivateKey,
    PrivateKeyPassphrase,
    SshPassword,
    ProxyPassword,
}

impl SecretPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Token => "token",
            Self::PrivateKey => "private-key",
            Self::PrivateKeyPassphrase => "private-key-passphrase",
            Self::SshPassword => "ssh-password",
            Self::ProxyPassword => "proxy-password",
        }
    }
}

pub fn connection_secret_ref(connection_id: &str, purpose: SecretPurpose) -> Result<SecretRef> {
    validate_handle_part("connection id", connection_id)?;
    Ok(SecretRef {
        handle: format!("connections/{connection_id}/{}", purpose.as_str()),
        service: Some(DEFAULT_SERVICE.to_string()),
    })
}

#[derive(Debug, Default)]
pub struct MemorySecureStore {
    secrets: Mutex<HashMap<String, String>>,
}

impl MemorySecureStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecureStore for MemorySecureStore {
    fn put(&self, handle: &SecretRef, value: SecretValue<'_>) -> Result<()> {
        validate_secret_ref(handle)?;
        self.secrets
            .lock()
            .map_err(|_| {
                IrodoriError::new(
                    irodori_core::IrodoriErrorKind::Internal,
                    "secret store lock poisoned",
                )
            })?
            .insert(account_name(handle), value.as_str().to_string());
        Ok(())
    }

    fn get(&self, handle: &SecretRef) -> Result<Option<String>> {
        validate_secret_ref(handle)?;
        Ok(self
            .secrets
            .lock()
            .map_err(|_| {
                IrodoriError::new(
                    irodori_core::IrodoriErrorKind::Internal,
                    "secret store lock poisoned",
                )
            })?
            .get(&account_name(handle))
            .cloned())
    }

    fn delete(&self, handle: &SecretRef) -> Result<()> {
        validate_secret_ref(handle)?;
        self.secrets
            .lock()
            .map_err(|_| {
                IrodoriError::new(
                    irodori_core::IrodoriErrorKind::Internal,
                    "secret store lock poisoned",
                )
            })?
            .remove(&account_name(handle));
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsKeychainStore {
    service: String,
}

impl OsKeychainStore {
    pub fn new(service: impl Into<String>) -> Result<Self> {
        let service = service.into();
        validate_handle_part("secret service", &service)?;
        Ok(Self { service })
    }

    pub fn default_service() -> Self {
        Self {
            service: DEFAULT_SERVICE.to_string(),
        }
    }
}

impl Default for OsKeychainStore {
    fn default() -> Self {
        Self::default_service()
    }
}

impl SecureStore for OsKeychainStore {
    fn put(&self, handle: &SecretRef, value: SecretValue<'_>) -> Result<()> {
        validate_secret_ref(handle)?;
        platform_put(
            &self.service_name(handle),
            &account_name(handle),
            value.as_str(),
        )
    }

    fn get(&self, handle: &SecretRef) -> Result<Option<String>> {
        validate_secret_ref(handle)?;
        platform_get(&self.service_name(handle), &account_name(handle))
    }

    fn delete(&self, handle: &SecretRef) -> Result<()> {
        validate_secret_ref(handle)?;
        platform_delete(&self.service_name(handle), &account_name(handle))
    }
}

impl OsKeychainStore {
    fn service_name(&self, handle: &SecretRef) -> String {
        handle
            .service
            .clone()
            .unwrap_or_else(|| self.service.clone())
    }
}

fn validate_secret_ref(handle: &SecretRef) -> Result<()> {
    validate_handle_part("secret handle", &handle.handle)?;
    if let Some(service) = &handle.service {
        validate_handle_part("secret service", service)?;
    }
    Ok(())
}

fn validate_handle_part(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(IrodoriError::validation(format!("{label} is required")));
    }
    if value.chars().any(char::is_control) {
        return Err(IrodoriError::validation(format!(
            "{label} cannot contain control characters"
        )));
    }
    Ok(())
}

fn account_name(handle: &SecretRef) -> String {
    handle.handle.clone()
}

#[cfg(target_os = "macos")]
fn platform_put(service: &str, account: &str, value: &str) -> Result<()> {
    let output = Command::new("security")
        .args([
            "add-generic-password",
            "-s",
            service,
            "-a",
            account,
            "-w",
            value,
            "-U",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(os_keychain_unavailable)?;
    command_ok(output.status.success(), "store secret in macOS keychain")
}

#[cfg(target_os = "macos")]
fn platform_get(service: &str, account: &str) -> Result<Option<String>> {
    let output = Command::new("security")
        .args(["find-generic-password", "-s", service, "-a", account, "-w"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(os_keychain_unavailable)?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(trim_trailing_newline(
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )))
}

#[cfg(target_os = "macos")]
fn platform_delete(service: &str, account: &str) -> Result<()> {
    let output = Command::new("security")
        .args(["delete-generic-password", "-s", service, "-a", account])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(os_keychain_unavailable)?;
    if output.status.success() {
        Ok(())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn platform_put(service: &str, account: &str, value: &str) -> Result<()> {
    let mut child = Command::new("secret-tool")
        .args([
            "store",
            "--label",
            "Irodori Table secret",
            "service",
            service,
            "account",
            account,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(os_keychain_unavailable)?;
    if let Some(stdin) = &mut child.stdin {
        use std::io::Write;
        stdin
            .write_all(value.as_bytes())
            .map_err(|_| IrodoriError::transport("failed to send secret to keychain"))?;
    }
    let status = child
        .wait()
        .map_err(|_| IrodoriError::transport("failed to wait for keychain command"))?;
    command_ok(status.success(), "store secret in Linux keyring")
}

#[cfg(target_os = "linux")]
fn platform_get(service: &str, account: &str) -> Result<Option<String>> {
    let output = Command::new("secret-tool")
        .args(["lookup", "service", service, "account", account])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(os_keychain_unavailable)?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(trim_trailing_newline(
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )))
}

#[cfg(target_os = "linux")]
fn platform_delete(service: &str, account: &str) -> Result<()> {
    Command::new("secret-tool")
        .args(["clear", "service", service, "account", account])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(os_keychain_unavailable)?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn platform_put(service: &str, account: &str, value: &str) -> Result<()> {
    use windows_sys::Win32::Security::Credentials::{
        CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
    };

    let blob = value.as_bytes();
    if blob.len() > WINDOWS_MAX_CREDENTIAL_BLOB_SIZE {
        return Err(IrodoriError::validation(format!(
            "secret value is too large for Windows Credential Manager generic credentials ({} bytes max)",
            WINDOWS_MAX_CREDENTIAL_BLOB_SIZE
        )));
    }

    let mut target: Vec<u16> = wide_null(&windows_target_name(service, account));
    let mut username: Vec<u16> = wide_null(account);
    let credential = CREDENTIALW {
        Flags: 0,
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_mut_ptr(),
        Comment: std::ptr::null_mut(),
        LastWritten: Default::default(),
        CredentialBlobSize: blob.len() as u32,
        CredentialBlob: blob.as_ptr() as *mut u8,
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        AttributeCount: 0,
        Attributes: std::ptr::null_mut(),
        TargetAlias: std::ptr::null_mut(),
        UserName: username.as_mut_ptr(),
    };

    let ok = unsafe { CredWriteW(&credential, 0) } != 0;
    if ok {
        Ok(())
    } else {
        Err(windows_credential_error("store secret"))
    }
}

#[cfg(target_os = "windows")]
fn platform_get(service: &str, account: &str) -> Result<Option<String>> {
    use windows_sys::Win32::Security::Credentials::{
        CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
    };

    let target: Vec<u16> = wide_null(&windows_target_name(service, account));
    let mut credential: *mut CREDENTIALW = std::ptr::null_mut();
    let ok = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) } != 0;
    if !ok {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(1168) {
            return Ok(None);
        }
        return Err(windows_credential_error_from("read secret", error));
    }
    if credential.is_null() {
        return Ok(None);
    }

    let result = unsafe {
        let credential_ref = &*credential;
        let blob = std::slice::from_raw_parts(
            credential_ref.CredentialBlob,
            credential_ref.CredentialBlobSize as usize,
        );
        String::from_utf8(blob.to_vec()).map_err(|_| {
            IrodoriError::new(
                irodori_core::IrodoriErrorKind::Internal,
                "Windows Credential Manager returned non-UTF-8 secret data",
            )
        })
    };
    unsafe {
        CredFree(credential.cast());
    }
    result.map(Some)
}

#[cfg(target_os = "windows")]
fn platform_delete(service: &str, account: &str) -> Result<()> {
    use windows_sys::Win32::Security::Credentials::{CredDeleteW, CRED_TYPE_GENERIC};

    let target: Vec<u16> = wide_null(&windows_target_name(service, account));
    let ok = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } != 0;
    if ok {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(1168) {
        Ok(())
    } else {
        Err(windows_credential_error_from("delete secret", error))
    }
}

#[cfg(target_os = "windows")]
fn windows_target_name(service: &str, account: &str) -> String {
    format!("{service}/{account}")
}

#[cfg(target_os = "windows")]
fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn windows_credential_error(action: &str) -> IrodoriError {
    windows_credential_error_from(action, std::io::Error::last_os_error())
}

#[cfg(target_os = "windows")]
fn windows_credential_error_from(action: &str, error: std::io::Error) -> IrodoriError {
    IrodoriError::transport(format!(
        "failed to {action} in Windows Credential Manager: {error}"
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn platform_put(_service: &str, _account: &str, _value: &str) -> Result<()> {
    Err(unsupported_keychain())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn platform_get(_service: &str, _account: &str) -> Result<Option<String>> {
    Err(unsupported_keychain())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn platform_delete(_service: &str, _account: &str) -> Result<()> {
    Err(unsupported_keychain())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn os_keychain_unavailable(error: std::io::Error) -> IrodoriError {
    IrodoriError::new(
        irodori_core::IrodoriErrorKind::Unsupported,
        format!("OS keychain command is unavailable: {error}"),
    )
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn command_ok(ok: bool, action: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(IrodoriError::transport(format!("failed to {action}")))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn unsupported_keychain() -> IrodoriError {
    IrodoriError::new(
        irodori_core::IrodoriErrorKind::Unsupported,
        "OS keychain integration is not available on this platform yet",
    )
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn trim_trailing_newline(mut value: String) -> String {
    while value.ends_with(['\n', '\r']) {
        value.pop();
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_connection_secret_refs_are_stable_and_secret_free() {
        let reference = connection_secret_ref("prod", SecretPurpose::Password).unwrap();

        assert_eq!(reference.service.as_deref(), Some(DEFAULT_SERVICE));
        assert_eq!(reference.handle, "connections/prod/password");
        assert!(!reference.handle.contains("supersecret"));
    }

    #[test]
    fn memory_secure_store_round_trips_and_deletes() {
        let store = MemorySecureStore::new();
        let handle = store
            .put_connection_secret(
                "prod",
                SecretPurpose::Password,
                SecretValue::new("supersecret").unwrap(),
            )
            .unwrap();

        assert_eq!(store.get(&handle).unwrap().as_deref(), Some("supersecret"));
        store.delete(&handle).unwrap();
        assert_eq!(store.get(&handle).unwrap(), None);
    }

    #[test]
    fn empty_secret_values_are_rejected() {
        let error = SecretValue::new("").unwrap_err();
        assert_eq!(error.kind, irodori_core::IrodoriErrorKind::Validation);
    }

    #[test]
    fn os_keychain_store_has_a_valid_default_service() {
        let store = OsKeychainStore::default();
        assert_eq!(store.service, DEFAULT_SERVICE);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_target_names_include_service_and_account() {
        assert_eq!(
            windows_target_name(DEFAULT_SERVICE, "connections/prod/password"),
            "irodori-table/connections/prod/password"
        );
    }
}
