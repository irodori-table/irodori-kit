//! Connection profiles, transports, and their portable (exportable) forms.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize, Serializer};
use ts_rs::TS;

use irodori_error::{IrodoriError, Result};

const MAX_PROFILE_ID_LEN: usize = 128;
const MAX_SOURCE_ID_LEN: usize = 128;
pub const CONNECTION_PROFILE_SCHEMA_VERSION: u16 = 2;
const MIN_SUPPORTED_CONNECTION_PROFILE_SCHEMA_VERSION: u16 = 1;

mod portable;

pub use portable::{
    ConnectionProfileExport, PortableAuthConfig, PortableAwsAuthSource, PortableAzureAuthSource,
    PortableConnectionProfile, PortableGcpAuthSource, PortableProxyAuthConfig,
    PortableProxyChainHop, PortableProxyChainTransport, PortableProxyHopConfig,
    PortableProxyTransport, PortableSshAuthConfig, PortableSshProxyHop, PortableSshTunnelTransport,
    PortableTlsConfig, PortableTransportConfig, SecretSlot, SecretSlotPurpose,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename = "ConnectionProfile", rename_all = "camelCase")]
pub struct DesktopConnectionProfile<Engine> {
    pub id: String,
    pub engine: Engine,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub user: Option<String>,
    /// Legacy plaintext credential accepted while saved desktop profiles migrate to `auth`.
    ///
    /// This field is intentionally deserialize-only so profile serialization cannot persist the
    /// plaintext value again.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "reject_legacy_password_serialization"
    )]
    #[ts(optional)]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "AuthConfig::is_none")]
    pub auth: AuthConfig,
    #[serde(default, skip_serializing_if = "TlsConfig::is_default")]
    pub tls: TlsConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub database: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub socket_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub transport: Option<TransportConfig>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub read_only: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, String>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn reject_legacy_password_serialization<S>(
    _password: &Option<String>,
    _serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    Err(serde::ser::Error::custom(
        "legacy plaintext password must be migrated to auth before serialization",
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ConnectionProfile {
    pub id: String,
    pub display_name: String,
    pub source: SourceKind,
    pub transport: TransportConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub database: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub user: Option<String>,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default, skip_serializing_if = "TlsConfig::is_default")]
    pub tls: TlsConfig,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, String>,
}

impl ConnectionProfile {
    pub fn validate(&self) -> Result<()> {
        validate_id("profile id", &self.id, MAX_PROFILE_ID_LEN)?;
        validate_required("display name", &self.display_name)?;
        self.source.validate()?;
        self.transport.validate()?;
        self.auth.validate()?;
        self.tls.validate()?;

        if matches!(self.transport, TransportConfig::LocalFile(_))
            && self.tls.resolve_enabled(false)
        {
            return Err(IrodoriError::validation(
                "TLS cannot be enabled for a local-file transport",
            ));
        }

        validate_optional_non_empty("database", self.database.as_deref())?;
        validate_optional_non_empty("user", self.user.as_deref())?;
        validate_options(&self.options)?;

        Ok(())
    }

    /// Resolve the typed TLS mode against legacy transport booleans.
    ///
    /// `TlsMode::Default` preserves the transport's existing behavior; every
    /// explicit profile mode overrides it.
    pub fn transport_tls_enabled(&self) -> bool {
        let legacy_transport_tls = match &self.transport {
            TransportConfig::Direct(config) => config.tls,
            TransportConfig::Socks5Proxy(config) | TransportConfig::HttpConnectProxy(config) => {
                config.tls
            }
            TransportConfig::Chain(config) => config.tls,
            TransportConfig::LocalFile(_) | TransportConfig::SshTunnel(_) => false,
        };
        self.tls.resolve_enabled(legacy_transport_tls)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct SourceKind {
    pub id: String,
    pub family: SourceFamily,
}

impl SourceKind {
    pub fn new(id: impl Into<String>, family: SourceFamily) -> Self {
        Self {
            id: id.into(),
            family,
        }
    }

    pub fn postgresql() -> Self {
        Self::new("postgresql", SourceFamily::Sql)
    }

    pub fn sqlite() -> Self {
        Self::new("sqlite", SourceFamily::Sql)
    }

    pub fn validate(&self) -> Result<()> {
        validate_id("source id", &self.id, MAX_SOURCE_ID_LEN)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum SourceFamily {
    Sql,
    Document,
    KeyValue,
    Graph,
    TimeSeries,
    Search,
    Warehouse,
    Lakehouse,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum TransportConfig {
    Direct(DirectTransport),
    LocalFile(LocalFileTransport),
    SshTunnel(SshTunnelTransport),
    Socks5Proxy(ProxyTransport),
    HttpConnectProxy(ProxyTransport),
    Chain(ProxyChainTransport),
}

impl TransportConfig {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Direct(config) => config.validate(),
            Self::LocalFile(config) => config.validate(),
            Self::SshTunnel(config) => config.validate(),
            Self::Socks5Proxy(config) | Self::HttpConnectProxy(config) => config.validate_route(),
            Self::Chain(config) => config.validate(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct DirectTransport {
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub port: Option<u16>,
    #[serde(default)]
    pub tls: bool,
}

impl DirectTransport {
    pub fn new(host: impl Into<String>, port: Option<u16>) -> Self {
        Self {
            host: host.into(),
            port,
            tls: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_required("host", &self.host)?;
        if self.port == Some(0) {
            return Err(IrodoriError::validation("port must be between 1 and 65535"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct LocalFileTransport {
    pub path: String,
}

impl LocalFileTransport {
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }

    pub fn validate(&self) -> Result<()> {
        validate_required("path", &self.path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct SshTunnelTransport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub name: Option<String>,
    pub ssh_host: String,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    pub username: String,
    #[serde(default)]
    pub auth: SshAuthConfig,
    pub target_host: String,
    pub target_port: u16,
    #[serde(default)]
    pub strict_host_key: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub host_key: Option<String>,
}

impl SshTunnelTransport {
    pub fn new(
        ssh_host: impl Into<String>,
        username: impl Into<String>,
        target_host: impl Into<String>,
        target_port: u16,
    ) -> Self {
        Self {
            name: None,
            ssh_host: ssh_host.into(),
            ssh_port: default_ssh_port(),
            username: username.into(),
            auth: SshAuthConfig::Agent,
            target_host: target_host.into(),
            target_port,
            strict_host_key: true,
            host_key: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_optional_id("tunnel name", self.name.as_deref())?;
        validate_required("ssh host", &self.ssh_host)?;
        validate_port("ssh port", self.ssh_port)?;
        validate_required("ssh username", &self.username)?;
        self.auth.validate()?;
        validate_required("target host", &self.target_host)?;
        validate_port("target port", self.target_port)?;
        validate_optional_non_empty("host key", self.host_key.as_deref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ProxyTransport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub name: Option<String>,
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub auth: Option<ProxyAuthConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub target_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub target_port: Option<u16>,
    #[serde(default)]
    pub tls: bool,
}

impl ProxyTransport {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            name: None,
            host: host.into(),
            port,
            auth: None,
            target_host: None,
            target_port: None,
            tls: false,
        }
    }

    pub fn with_target(mut self, target_host: impl Into<String>, target_port: u16) -> Self {
        self.target_host = Some(target_host.into());
        self.target_port = Some(target_port);
        self
    }

    fn validate_server(&self) -> Result<()> {
        validate_optional_id("proxy name", self.name.as_deref())?;
        validate_required("proxy host", &self.host)?;
        validate_port("proxy port", self.port)?;
        if let Some(auth) = &self.auth {
            auth.validate()?;
        }
        Ok(())
    }

    fn validate_route(&self) -> Result<()> {
        self.validate_server()?;
        validate_required(
            "proxy target host",
            self.target_host.as_deref().unwrap_or(""),
        )?;
        let target_port = self
            .target_port
            .ok_or_else(|| IrodoriError::validation("proxy target port is required"))?;
        validate_port("proxy target port", target_port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ProxyAuthConfig {
    pub username: String,
    pub password: SecretRef,
}

impl ProxyAuthConfig {
    fn validate(&self) -> Result<()> {
        validate_required("proxy username", &self.username)?;
        self.password.validate("proxy password handle")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ProxyChainTransport {
    pub target_host: String,
    pub target_port: u16,
    #[serde(default)]
    pub tls: bool,
    pub hops: Vec<ProxyChainHop>,
}

impl ProxyChainTransport {
    pub fn new(target_host: impl Into<String>, target_port: u16, hops: Vec<ProxyChainHop>) -> Self {
        Self {
            target_host: target_host.into(),
            target_port,
            tls: false,
            hops,
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_required("chain target host", &self.target_host)?;
        validate_port("chain target port", self.target_port)?;
        if self.hops.len() < 2 {
            return Err(IrodoriError::validation(
                "proxy chain must contain at least two named hops",
            ));
        }

        let mut names = BTreeSet::new();
        for hop in &self.hops {
            hop.validate()?;
            if !names.insert(hop.name.as_str()) {
                return Err(IrodoriError::validation(format!(
                    "proxy chain hop `{}` is duplicated",
                    hop.name
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ProxyChainHop {
    pub name: String,
    pub config: ProxyHopConfig,
}

impl ProxyChainHop {
    pub fn new(name: impl Into<String>, config: ProxyHopConfig) -> Self {
        Self {
            name: name.into(),
            config,
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_id("proxy hop name", &self.name, MAX_PROFILE_ID_LEN)?;
        self.config.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum ProxyHopConfig {
    Ssh(SshProxyHop),
    Socks5(ProxyTransport),
    HttpConnect(ProxyTransport),
}

impl ProxyHopConfig {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Ssh(config) => config.validate(),
            Self::Socks5(config) | Self::HttpConnect(config) => config.validate_server(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct SshProxyHop {
    pub ssh_host: String,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    pub username: String,
    #[serde(default)]
    pub auth: SshAuthConfig,
    #[serde(default)]
    pub strict_host_key: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub host_key: Option<String>,
}

impl SshProxyHop {
    pub fn new(ssh_host: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            ssh_host: ssh_host.into(),
            ssh_port: default_ssh_port(),
            username: username.into(),
            auth: SshAuthConfig::Agent,
            strict_host_key: true,
            host_key: None,
        }
    }

    fn validate(&self) -> Result<()> {
        validate_required("ssh host", &self.ssh_host)?;
        validate_port("ssh port", self.ssh_port)?;
        validate_required("ssh username", &self.username)?;
        self.auth.validate()?;
        validate_optional_non_empty("host key", self.host_key.as_deref())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[ts(rename_all = "camelCase")]
pub enum SshAuthConfig {
    #[default]
    Agent,
    Password {
        password: SecretRef,
    },
    PrivateKey {
        #[serde(alias = "private_key")]
        private_key: SecretRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        passphrase: Option<SecretRef>,
    },
}

impl SshAuthConfig {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Agent => Ok(()),
            Self::Password { password } => password.validate("ssh password handle"),
            Self::PrivateKey {
                private_key,
                passphrase,
            } => {
                private_key.validate("ssh private key handle")?;
                if let Some(passphrase) = passphrase {
                    passphrase.validate("ssh private key passphrase handle")?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
pub enum JwtAlgorithm {
    #[default]
    #[serde(rename = "RS256")]
    #[ts(rename = "RS256")]
    Rs256,
    #[serde(rename = "RS384")]
    #[ts(rename = "RS384")]
    Rs384,
    #[serde(rename = "RS512")]
    #[ts(rename = "RS512")]
    Rs512,
    #[serde(rename = "ES256")]
    #[ts(rename = "ES256")]
    Es256,
    #[serde(rename = "ES384")]
    #[ts(rename = "ES384")]
    Es384,
    #[serde(rename = "EdDSA")]
    #[ts(rename = "EdDSA")]
    EdDsa,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum OAuth2Flow {
    AuthorizationCode,
    ClientCredentials,
    DeviceCode,
    RefreshToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[ts(rename_all = "camelCase")]
pub enum AwsAuthSource {
    Chain,
    Static {
        access_key_id: String,
        secret_access_key: SecretRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        session_token: Option<SecretRef>,
    },
    Profile {
        profile_name: String,
    },
    Sso {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        profile_name: Option<String>,
    },
    WebIdentity {
        role_arn: String,
        token: SecretRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        session_name: Option<String>,
    },
    AssumeRole {
        role_arn: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        source_profile: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        external_id: Option<SecretRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        session_name: Option<String>,
    },
}

impl AwsAuthSource {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Chain => Ok(()),
            Self::Static {
                access_key_id,
                secret_access_key,
                session_token,
            } => {
                validate_required("AWS access key id", access_key_id)?;
                secret_access_key.validate("AWS secret access key handle")?;
                validate_optional_secret("AWS session token handle", session_token)
            }
            Self::Profile { profile_name } => validate_required("AWS profile name", profile_name),
            Self::Sso { profile_name } => {
                validate_optional_non_empty("AWS SSO profile name", profile_name.as_deref())
            }
            Self::WebIdentity {
                role_arn,
                token,
                session_name,
            } => {
                validate_required("AWS role ARN", role_arn)?;
                token.validate("AWS web identity token handle")?;
                validate_optional_non_empty("AWS role session name", session_name.as_deref())
            }
            Self::AssumeRole {
                role_arn,
                source_profile,
                external_id,
                session_name,
            } => {
                validate_required("AWS role ARN", role_arn)?;
                validate_optional_non_empty("AWS source profile", source_profile.as_deref())?;
                validate_optional_secret("AWS external id handle", external_id)?;
                validate_optional_non_empty("AWS role session name", session_name.as_deref())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[ts(rename_all = "camelCase")]
pub enum GcpAuthSource {
    Adc,
    ServiceAccountJson {
        credentials: SecretRef,
    },
    Impersonation {
        target_principal: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        delegates: Vec<String>,
    },
    WorkloadIdentity {
        audience: String,
        subject_token: SecretRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        service_account_impersonation_url: Option<String>,
    },
}

impl GcpAuthSource {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Adc => Ok(()),
            Self::ServiceAccountJson { credentials } => {
                credentials.validate("GCP service account JSON handle")
            }
            Self::Impersonation {
                target_principal,
                delegates,
            } => {
                validate_required("GCP target principal", target_principal)?;
                validate_string_list("GCP delegate", delegates)
            }
            Self::WorkloadIdentity {
                audience,
                subject_token,
                service_account_impersonation_url,
            } => {
                validate_required("GCP workload identity audience", audience)?;
                subject_token.validate("GCP subject token handle")?;
                if let Some(url) = service_account_impersonation_url {
                    validate_secure_url("GCP service account impersonation URL", url)?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[ts(rename_all = "camelCase")]
pub enum AzureAuthSource {
    Cli,
    ManagedIdentity {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        client_id: Option<String>,
    },
    ServicePrincipal {
        tenant_id: String,
        client_id: String,
        client_secret: SecretRef,
    },
    ServicePrincipalCertificate {
        tenant_id: String,
        client_id: String,
        certificate: SecretRef,
        private_key: SecretRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        passphrase: Option<SecretRef>,
    },
}

impl AzureAuthSource {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Cli => Ok(()),
            Self::ManagedIdentity { client_id } => validate_optional_non_empty(
                "Azure managed identity client id",
                client_id.as_deref(),
            ),
            Self::ServicePrincipal {
                tenant_id,
                client_id,
                client_secret,
            } => {
                validate_required("Azure tenant id", tenant_id)?;
                validate_required("Azure client id", client_id)?;
                client_secret.validate("Azure client secret handle")
            }
            Self::ServicePrincipalCertificate {
                tenant_id,
                client_id,
                certificate,
                private_key,
                passphrase,
            } => {
                validate_required("Azure tenant id", tenant_id)?;
                validate_required("Azure client id", client_id)?;
                certificate.validate("Azure client certificate handle")?;
                private_key.validate("Azure private key handle")?;
                validate_optional_secret("Azure private key passphrase handle", passphrase)
            }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[ts(rename_all = "camelCase")]
pub enum AuthConfig {
    #[default]
    None,
    #[serde(alias = "secret")]
    Password {
        #[serde(alias = "secret")]
        password: SecretRef,
    },
    Token {
        token: SecretRef,
    },
    ApiKey {
        api_key: SecretRef,
    },
    #[serde(alias = "keyPair")]
    KeyPairJwt {
        #[serde(alias = "private_key")]
        private_key: SecretRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        passphrase: Option<SecretRef>,
        #[serde(default)]
        algorithm: JwtAlgorithm,
    },
    ClientCertificate {
        cert: SecretRef,
        key: SecretRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        passphrase: Option<SecretRef>,
    },
    Kerberos {
        principal: String,
        keytab: SecretRef,
        service_name: String,
    },
    #[serde(rename = "oauth2")]
    #[ts(rename = "oauth2")]
    OAuth2 {
        flow: OAuth2Flow,
        client_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        client_secret: Option<SecretRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        refresh_token: Option<SecretRef>,
        token_endpoint: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        scopes: Vec<String>,
    },
    ExternalBrowser {
        authorize_endpoint: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        redirect_port: Option<u16>,
    },
    Aws {
        source: AwsAuthSource,
    },
    Gcp {
        source: GcpAuthSource,
    },
    Azure {
        source: AzureAuthSource,
    },
}

impl AuthConfig {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::None => Ok(()),
            Self::Password { password } => password.validate("password handle"),
            Self::Token { token } => token.validate("token handle"),
            Self::ApiKey { api_key } => api_key.validate("API key handle"),
            Self::KeyPairJwt {
                private_key,
                passphrase,
                ..
            } => {
                private_key.validate("private key handle")?;
                validate_optional_secret("passphrase handle", passphrase)
            }
            Self::ClientCertificate {
                cert,
                key,
                passphrase,
            } => {
                cert.validate("client certificate handle")?;
                key.validate("client certificate key handle")?;
                validate_optional_secret("client certificate passphrase handle", passphrase)
            }
            Self::Kerberos {
                principal,
                keytab,
                service_name,
            } => {
                validate_required("Kerberos principal", principal)?;
                keytab.validate("Kerberos keytab handle")?;
                validate_required("Kerberos service name", service_name)
            }
            Self::OAuth2 {
                flow,
                client_id,
                client_secret,
                refresh_token,
                token_endpoint,
                scopes,
            } => {
                validate_required("OAuth2 client id", client_id)?;
                validate_optional_secret("OAuth2 client secret handle", client_secret)?;
                validate_optional_secret("OAuth2 refresh token handle", refresh_token)?;
                if *flow == OAuth2Flow::ClientCredentials && client_secret.is_none() {
                    return Err(IrodoriError::validation(
                        "OAuth2 client-credentials flow requires a client secret",
                    ));
                }
                if *flow == OAuth2Flow::RefreshToken && refresh_token.is_none() {
                    return Err(IrodoriError::validation(
                        "OAuth2 refresh-token flow requires a refresh token",
                    ));
                }
                validate_secure_url("OAuth2 token endpoint", token_endpoint)?;
                validate_string_list("OAuth2 scope", scopes)
            }
            Self::ExternalBrowser {
                authorize_endpoint,
                redirect_port,
            } => {
                validate_secure_url("external browser authorize endpoint", authorize_endpoint)?;
                if *redirect_port == Some(0) {
                    return Err(IrodoriError::validation(
                        "external browser redirect port must be between 1 and 65535",
                    ));
                }
                Ok(())
            }
            Self::Aws { source } => source.validate(),
            Self::Gcp { source } => source.validate(),
            Self::Azure { source } => source.validate(),
        }
    }

    fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum TlsMode {
    #[default]
    Default,
    Disable,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
    ClientCertificate,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct TlsConfig {
    #[serde(default)]
    pub mode: TlsMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub root_cert: Option<SecretRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub client_cert: Option<SecretRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub client_key: Option<SecretRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub server_name: Option<String>,
}

impl TlsConfig {
    pub fn resolve_enabled(&self, legacy_transport_tls: bool) -> bool {
        match self.mode {
            TlsMode::Default => legacy_transport_tls,
            TlsMode::Disable => false,
            TlsMode::Prefer
            | TlsMode::Require
            | TlsMode::VerifyCa
            | TlsMode::VerifyFull
            | TlsMode::ClientCertificate => true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_optional_secret("TLS root certificate handle", &self.root_cert)?;
        validate_optional_secret("TLS client certificate handle", &self.client_cert)?;
        validate_optional_secret("TLS client key handle", &self.client_key)?;
        validate_optional_non_empty("TLS server name", self.server_name.as_deref())?;

        if self.client_cert.is_some() != self.client_key.is_some() {
            return Err(IrodoriError::validation(
                "TLS client certificate and client key must be configured together",
            ));
        }
        if self.mode == TlsMode::ClientCertificate && self.client_cert.is_none() {
            return Err(IrodoriError::validation(
                "client-certificate TLS mode requires a client certificate and key",
            ));
        }
        if matches!(self.mode, TlsMode::Default | TlsMode::Disable)
            && (self.root_cert.is_some()
                || self.client_cert.is_some()
                || self.client_key.is_some()
                || self.server_name.is_some())
        {
            return Err(IrodoriError::validation(
                "TLS certificate and server-name options require an explicit enabled TLS mode",
            ));
        }
        Ok(())
    }

    fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct SecretRef {
    pub handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub service: Option<String>,
}

impl SecretRef {
    pub fn new(handle: impl Into<String>) -> Self {
        Self {
            handle: handle.into(),
            service: None,
        }
    }

    fn validate(&self, label: &str) -> Result<()> {
        validate_required(label, &self.handle)?;
        validate_optional_non_empty("secret service", self.service.as_deref())
    }
}

fn validate_optional_secret(label: &str, secret: &Option<SecretRef>) -> Result<()> {
    if let Some(secret) = secret {
        secret.validate(label)?;
    }
    Ok(())
}

fn validate_string_list(label: &str, values: &[String]) -> Result<()> {
    for value in values {
        validate_required(label, value)?;
    }
    Ok(())
}

fn validate_id(label: &str, value: &str, max_len: usize) -> Result<()> {
    validate_required(label, value)?;
    if value.len() > max_len {
        return Err(IrodoriError::validation(format!(
            "{label} must be {max_len} characters or fewer"
        )));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(IrodoriError::validation(format!(
            "{label} cannot contain whitespace"
        )));
    }
    Ok(())
}

fn validate_optional_id(label: &str, value: Option<&str>) -> Result<()> {
    if let Some(value) = value {
        validate_id(label, value, MAX_PROFILE_ID_LEN)?;
    }
    Ok(())
}

fn validate_required(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(IrodoriError::validation(format!("{label} is required")));
    }
    Ok(())
}

fn validate_port(label: &str, port: u16) -> Result<()> {
    if port == 0 {
        return Err(IrodoriError::validation(format!(
            "{label} must be between 1 and 65535"
        )));
    }
    Ok(())
}

fn validate_optional_non_empty(label: &str, value: Option<&str>) -> Result<()> {
    if matches!(value, Some(value) if value.trim().is_empty()) {
        return Err(IrodoriError::validation(format!(
            "{label} cannot be empty when set"
        )));
    }
    Ok(())
}

fn validate_secure_url(label: &str, value: &str) -> Result<()> {
    validate_required(label, value)?;
    let (secure, rest) = if let Some(rest) = value.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = value.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(IrodoriError::validation(format!(
            "{label} must be an absolute HTTPS URL"
        )));
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err(IrodoriError::validation(format!(
            "{label} must contain a valid host without embedded credentials"
        )));
    }
    let loopback = authority == "localhost"
        || authority.starts_with("localhost:")
        || authority == "127.0.0.1"
        || authority.starts_with("127.0.0.1:")
        || authority == "[::1]"
        || authority.starts_with("[::1]:");
    if !secure && !loopback {
        return Err(IrodoriError::validation(format!(
            "{label} must use HTTPS except for loopback development URLs"
        )));
    }
    Ok(())
}

fn default_ssh_port() -> u16 {
    22
}

fn validate_options(options: &BTreeMap<String, String>) -> Result<()> {
    for key in options.keys() {
        validate_required("option key", key)?;
        let normalized = key.to_ascii_lowercase().replace(['_', '-'], "");
        let secret_suffixes = [
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "apikey",
            "privatekey",
            "passphrase",
            "clientcertificate",
            "clientkey",
            "keytab",
            "accesskey",
            "credential",
            "credentials",
            "credentialsjson",
            "serviceaccountjson",
            "externalid",
            "rootcert",
        ];
        if secret_suffixes
            .iter()
            .any(|suffix| normalized.ends_with(suffix))
        {
            return Err(IrodoriError::validation(format!(
                "option `{key}` must be stored as a secret handle"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
