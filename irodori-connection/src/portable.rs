use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use irodori_error::{IrodoriError, Result};

use super::{
    validate_id, validate_optional_id, validate_optional_non_empty, validate_options,
    validate_port, validate_required, validate_secure_url, validate_string_list, AuthConfig,
    AwsAuthSource, AzureAuthSource, ConnectionProfile, DirectTransport, GcpAuthSource,
    JwtAlgorithm, LocalFileTransport, OAuth2Flow, ProxyAuthConfig, ProxyChainHop,
    ProxyChainTransport, ProxyHopConfig, ProxyTransport, SourceKind, SshAuthConfig, SshProxyHop,
    SshTunnelTransport, TlsConfig, TlsMode, TransportConfig, CONNECTION_PROFILE_SCHEMA_VERSION,
    MAX_PROFILE_ID_LEN, MIN_SUPPORTED_CONNECTION_PROFILE_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ConnectionProfileExport {
    pub schema_version: u16,
    pub profiles: Vec<PortableConnectionProfile>,
}

impl ConnectionProfileExport {
    pub fn from_profiles<'a>(
        profiles: impl IntoIterator<Item = &'a ConnectionProfile>,
    ) -> Result<Self> {
        let mut portable_profiles = Vec::new();
        let mut profile_ids = BTreeSet::new();
        for profile in profiles {
            profile.validate()?;
            if !profile_ids.insert(&profile.id) {
                return Err(IrodoriError::validation(format!(
                    "connection profile id `{}` is duplicated in the export",
                    profile.id
                )));
            }
            let portable = PortableConnectionProfile::from_profile(profile);
            portable.validate()?;
            portable_profiles.push(portable);
        }

        Ok(Self {
            schema_version: CONNECTION_PROFILE_SCHEMA_VERSION,
            profiles: portable_profiles,
        })
    }

    pub fn validate_schema_version(&self) -> Result<()> {
        if (MIN_SUPPORTED_CONNECTION_PROFILE_SCHEMA_VERSION..=CONNECTION_PROFILE_SCHEMA_VERSION)
            .contains(&self.schema_version)
        {
            Ok(())
        } else {
            Err(IrodoriError::validation(format!(
                "connection profile schema version {} is not supported; expected {} through {}",
                self.schema_version,
                MIN_SUPPORTED_CONNECTION_PROFILE_SCHEMA_VERSION,
                CONNECTION_PROFILE_SCHEMA_VERSION,
            )))
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_schema_version()?;
        let mut profile_ids = BTreeSet::new();
        for profile in &self.profiles {
            if !profile_ids.insert(&profile.id) {
                return Err(IrodoriError::validation(format!(
                    "connection profile id `{}` is duplicated in the export",
                    profile.id
                )));
            }
            profile.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct PortableConnectionProfile {
    pub id: String,
    pub display_name: String,
    pub source: SourceKind,
    pub transport: PortableTransportConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub database: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub user: Option<String>,
    #[serde(default)]
    pub auth: PortableAuthConfig,
    #[serde(default, skip_serializing_if = "PortableTlsConfig::is_default")]
    pub tls: PortableTlsConfig,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, String>,
}

impl PortableConnectionProfile {
    pub fn from_profile(profile: &ConnectionProfile) -> Self {
        Self {
            id: profile.id.clone(),
            display_name: profile.display_name.clone(),
            source: profile.source.clone(),
            transport: PortableTransportConfig::from_transport(&profile.transport),
            database: profile.database.clone(),
            user: profile.user.clone(),
            auth: PortableAuthConfig::from_auth(&profile.auth),
            tls: PortableTlsConfig::from_tls(&profile.tls),
            options: profile.options.clone(),
        }
    }

    pub fn required_secret_slots(&self) -> Vec<SecretSlot> {
        let mut slots = Vec::new();
        self.auth.append_secret_slots(&self.id, "auth", &mut slots);
        self.tls.append_secret_slots(&self.id, "tls", &mut slots);
        self.transport.append_secret_slots(&self.id, &mut slots);
        slots
    }

    pub fn validate(&self) -> Result<()> {
        validate_id("profile id", &self.id, MAX_PROFILE_ID_LEN)?;
        validate_required("display name", &self.display_name)?;
        self.source.validate()?;
        self.transport.validate()?;
        validate_optional_non_empty("database", self.database.as_deref())?;
        validate_optional_non_empty("user", self.user.as_deref())?;
        validate_options(&self.options)?;
        self.auth.validate()?;
        self.tls.validate()?;
        if matches!(self.transport, PortableTransportConfig::LocalFile(_))
            && !matches!(self.tls.mode, TlsMode::Default | TlsMode::Disable)
        {
            return Err(IrodoriError::validation(
                "TLS cannot be enabled for a local-file transport",
            ));
        }
        let slots = self.required_secret_slots();
        let mut paths = BTreeSet::new();
        for slot in slots {
            if !paths.insert(slot.path.clone()) {
                return Err(IrodoriError::validation(format!(
                    "portable profile `{}` contains duplicate secret slot path `{}`",
                    self.id, slot.path
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum PortableTransportConfig {
    Direct(DirectTransport),
    LocalFile(LocalFileTransport),
    SshTunnel(PortableSshTunnelTransport),
    Socks5Proxy(PortableProxyTransport),
    HttpConnectProxy(PortableProxyTransport),
    Chain(PortableProxyChainTransport),
}

impl PortableTransportConfig {
    fn from_transport(transport: &TransportConfig) -> Self {
        match transport {
            TransportConfig::Direct(config) => Self::Direct(config.clone()),
            TransportConfig::LocalFile(config) => Self::LocalFile(config.clone()),
            TransportConfig::SshTunnel(config) => {
                Self::SshTunnel(PortableSshTunnelTransport::from_transport(config))
            }
            TransportConfig::Socks5Proxy(config) => {
                Self::Socks5Proxy(PortableProxyTransport::from_transport(config))
            }
            TransportConfig::HttpConnectProxy(config) => {
                Self::HttpConnectProxy(PortableProxyTransport::from_transport(config))
            }
            TransportConfig::Chain(config) => {
                Self::Chain(PortableProxyChainTransport::from_transport(config))
            }
        }
    }

    fn append_secret_slots(&self, profile_id: &str, slots: &mut Vec<SecretSlot>) {
        match self {
            Self::Direct(_) | Self::LocalFile(_) => {}
            Self::SshTunnel(config) => config.append_secret_slots(profile_id, slots),
            Self::Socks5Proxy(config) | Self::HttpConnectProxy(config) => {
                config.append_secret_slots(profile_id, "transport.proxy", slots);
            }
            Self::Chain(config) => config.append_secret_slots(profile_id, slots),
        }
    }

    fn validate(&self) -> Result<()> {
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
pub struct PortableSshTunnelTransport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub name: Option<String>,
    pub ssh_host: String,
    pub ssh_port: u16,
    pub username: String,
    #[serde(default)]
    pub auth: PortableSshAuthConfig,
    pub target_host: String,
    pub target_port: u16,
    #[serde(default)]
    pub strict_host_key: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub host_key: Option<String>,
}

impl PortableSshTunnelTransport {
    fn from_transport(transport: &SshTunnelTransport) -> Self {
        Self {
            name: transport.name.clone(),
            ssh_host: transport.ssh_host.clone(),
            ssh_port: transport.ssh_port,
            username: transport.username.clone(),
            auth: PortableSshAuthConfig::from_ssh_auth(&transport.auth),
            target_host: transport.target_host.clone(),
            target_port: transport.target_port,
            strict_host_key: transport.strict_host_key,
            host_key: transport.host_key.clone(),
        }
    }

    fn append_secret_slots(&self, profile_id: &str, slots: &mut Vec<SecretSlot>) {
        self.auth
            .append_secret_slots(profile_id, "transport.ssh", slots);
    }

    fn validate(&self) -> Result<()> {
        validate_optional_id("tunnel name", self.name.as_deref())?;
        validate_required("ssh host", &self.ssh_host)?;
        validate_port("ssh port", self.ssh_port)?;
        validate_required("ssh username", &self.username)?;
        validate_required("target host", &self.target_host)?;
        validate_port("target port", self.target_port)?;
        validate_optional_non_empty("host key", self.host_key.as_deref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct PortableProxyTransport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub name: Option<String>,
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub auth: Option<PortableProxyAuthConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub target_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub target_port: Option<u16>,
    #[serde(default)]
    pub tls: bool,
}

impl PortableProxyTransport {
    fn from_transport(transport: &ProxyTransport) -> Self {
        Self {
            name: transport.name.clone(),
            host: transport.host.clone(),
            port: transport.port,
            auth: transport
                .auth
                .as_ref()
                .map(PortableProxyAuthConfig::from_auth),
            target_host: transport.target_host.clone(),
            target_port: transport.target_port,
            tls: transport.tls,
        }
    }

    fn append_secret_slots(&self, profile_id: &str, path: &str, slots: &mut Vec<SecretSlot>) {
        if self.auth.is_some() {
            slots.push(SecretSlot::new(
                profile_id,
                format!("{path}.password"),
                SecretSlotPurpose::ProxyPassword,
            ));
        }
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
        match (&self.target_host, self.target_port) {
            (Some(host), Some(port)) => {
                validate_required("proxy target host", host)?;
                validate_port("proxy target port", port)
            }
            (None, None) => Err(IrodoriError::validation(
                "proxy target host and port are required",
            )),
            _ => Err(IrodoriError::validation(
                "proxy target host and port must be configured together",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct PortableProxyAuthConfig {
    pub username: String,
    pub password_required: bool,
}

impl PortableProxyAuthConfig {
    fn from_auth(auth: &ProxyAuthConfig) -> Self {
        Self {
            username: auth.username.clone(),
            password_required: true,
        }
    }

    fn validate(&self) -> Result<()> {
        validate_required("proxy username", &self.username)?;
        if !self.password_required {
            return Err(IrodoriError::validation(
                "portable proxy authentication requires a password slot",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct PortableProxyChainTransport {
    pub target_host: String,
    pub target_port: u16,
    #[serde(default)]
    pub tls: bool,
    pub hops: Vec<PortableProxyChainHop>,
}

impl PortableProxyChainTransport {
    fn from_transport(transport: &ProxyChainTransport) -> Self {
        Self {
            target_host: transport.target_host.clone(),
            target_port: transport.target_port,
            tls: transport.tls,
            hops: transport
                .hops
                .iter()
                .map(PortableProxyChainHop::from_hop)
                .collect(),
        }
    }

    fn append_secret_slots(&self, profile_id: &str, slots: &mut Vec<SecretSlot>) {
        for hop in &self.hops {
            hop.append_secret_slots(profile_id, slots);
        }
    }

    fn validate(&self) -> Result<()> {
        validate_required("chain target host", &self.target_host)?;
        validate_port("chain target port", self.target_port)?;
        if self.hops.len() < 2 {
            return Err(IrodoriError::validation(
                "proxy chain must contain at least two hops",
            ));
        }
        let mut names = BTreeSet::new();
        for hop in &self.hops {
            hop.validate()?;
            if !names.insert(&hop.name) {
                return Err(IrodoriError::validation(format!(
                    "proxy hop name `{}` is duplicated",
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
pub struct PortableProxyChainHop {
    pub name: String,
    pub config: PortableProxyHopConfig,
}

impl PortableProxyChainHop {
    fn from_hop(hop: &ProxyChainHop) -> Self {
        Self {
            name: hop.name.clone(),
            config: PortableProxyHopConfig::from_hop_config(&hop.config),
        }
    }

    fn append_secret_slots(&self, profile_id: &str, slots: &mut Vec<SecretSlot>) {
        self.config.append_secret_slots(
            profile_id,
            &format!("transport.chain.{}", self.name),
            slots,
        );
    }

    fn validate(&self) -> Result<()> {
        validate_id("proxy hop name", &self.name, MAX_PROFILE_ID_LEN)?;
        self.config.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum PortableProxyHopConfig {
    Ssh(PortableSshProxyHop),
    Socks5(PortableProxyTransport),
    HttpConnect(PortableProxyTransport),
}

impl PortableProxyHopConfig {
    fn from_hop_config(config: &ProxyHopConfig) -> Self {
        match config {
            ProxyHopConfig::Ssh(config) => Self::Ssh(PortableSshProxyHop::from_hop(config)),
            ProxyHopConfig::Socks5(config) => {
                Self::Socks5(PortableProxyTransport::from_transport(config))
            }
            ProxyHopConfig::HttpConnect(config) => {
                Self::HttpConnect(PortableProxyTransport::from_transport(config))
            }
        }
    }

    fn append_secret_slots(&self, profile_id: &str, path: &str, slots: &mut Vec<SecretSlot>) {
        match self {
            Self::Ssh(config) => config.append_secret_slots(profile_id, path, slots),
            Self::Socks5(config) | Self::HttpConnect(config) => {
                config.append_secret_slots(profile_id, path, slots);
            }
        }
    }

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
pub struct PortableSshProxyHop {
    pub ssh_host: String,
    pub ssh_port: u16,
    pub username: String,
    #[serde(default)]
    pub auth: PortableSshAuthConfig,
    #[serde(default)]
    pub strict_host_key: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub host_key: Option<String>,
}

impl PortableSshProxyHop {
    fn from_hop(hop: &SshProxyHop) -> Self {
        Self {
            ssh_host: hop.ssh_host.clone(),
            ssh_port: hop.ssh_port,
            username: hop.username.clone(),
            auth: PortableSshAuthConfig::from_ssh_auth(&hop.auth),
            strict_host_key: hop.strict_host_key,
            host_key: hop.host_key.clone(),
        }
    }

    fn append_secret_slots(&self, profile_id: &str, path: &str, slots: &mut Vec<SecretSlot>) {
        self.auth
            .append_secret_slots(profile_id, &format!("{path}.ssh"), slots);
    }

    fn validate(&self) -> Result<()> {
        validate_required("ssh host", &self.ssh_host)?;
        validate_port("ssh port", self.ssh_port)?;
        validate_required("ssh username", &self.username)?;
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
pub enum PortableSshAuthConfig {
    #[default]
    Agent,
    PasswordRequired,
    PrivateKeyRequired {
        #[serde(alias = "passphrase_required")]
        passphrase_required: bool,
    },
}

impl PortableSshAuthConfig {
    fn from_ssh_auth(auth: &SshAuthConfig) -> Self {
        match auth {
            SshAuthConfig::Agent => Self::Agent,
            SshAuthConfig::Password { .. } => Self::PasswordRequired,
            SshAuthConfig::PrivateKey { passphrase, .. } => Self::PrivateKeyRequired {
                passphrase_required: passphrase.is_some(),
            },
        }
    }

    fn append_secret_slots(&self, profile_id: &str, path: &str, slots: &mut Vec<SecretSlot>) {
        match self {
            Self::Agent => {}
            Self::PasswordRequired => slots.push(SecretSlot::new(
                profile_id,
                format!("{path}.password"),
                SecretSlotPurpose::SshPassword,
            )),
            Self::PrivateKeyRequired {
                passphrase_required,
            } => {
                slots.push(SecretSlot::new(
                    profile_id,
                    format!("{path}.privateKey"),
                    SecretSlotPurpose::PrivateKey,
                ));
                if *passphrase_required {
                    slots.push(SecretSlot::new(
                        profile_id,
                        format!("{path}.passphrase"),
                        SecretSlotPurpose::Passphrase,
                    ));
                }
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
pub enum PortableAwsAuthSource {
    Chain,
    Static {
        access_key_id: String,
        session_token_required: bool,
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        session_name: Option<String>,
    },
    AssumeRole {
        role_arn: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        source_profile: Option<String>,
        external_id_required: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        session_name: Option<String>,
    },
}

impl PortableAwsAuthSource {
    fn from_source(source: &AwsAuthSource) -> Self {
        match source {
            AwsAuthSource::Chain => Self::Chain,
            AwsAuthSource::Static {
                access_key_id,
                session_token,
                ..
            } => Self::Static {
                access_key_id: access_key_id.clone(),
                session_token_required: session_token.is_some(),
            },
            AwsAuthSource::Profile { profile_name } => Self::Profile {
                profile_name: profile_name.clone(),
            },
            AwsAuthSource::Sso { profile_name } => Self::Sso {
                profile_name: profile_name.clone(),
            },
            AwsAuthSource::WebIdentity {
                role_arn,
                session_name,
                ..
            } => Self::WebIdentity {
                role_arn: role_arn.clone(),
                session_name: session_name.clone(),
            },
            AwsAuthSource::AssumeRole {
                role_arn,
                source_profile,
                external_id,
                session_name,
            } => Self::AssumeRole {
                role_arn: role_arn.clone(),
                source_profile: source_profile.clone(),
                external_id_required: external_id.is_some(),
                session_name: session_name.clone(),
            },
        }
    }

    fn append_secret_slots(&self, profile_id: &str, path: &str, slots: &mut Vec<SecretSlot>) {
        match self {
            Self::Static {
                session_token_required,
                ..
            } => {
                slots.push(SecretSlot::new(
                    profile_id,
                    format!("{path}.secretAccessKey"),
                    SecretSlotPurpose::AwsSecretAccessKey,
                ));
                if *session_token_required {
                    slots.push(SecretSlot::new(
                        profile_id,
                        format!("{path}.sessionToken"),
                        SecretSlotPurpose::AwsSessionToken,
                    ));
                }
            }
            Self::WebIdentity { .. } => slots.push(SecretSlot::new(
                profile_id,
                format!("{path}.token"),
                SecretSlotPurpose::AwsWebIdentityToken,
            )),
            Self::AssumeRole {
                external_id_required,
                ..
            } if *external_id_required => {
                slots.push(SecretSlot::new(
                    profile_id,
                    format!("{path}.externalId"),
                    SecretSlotPurpose::AwsExternalId,
                ));
            }
            Self::Chain | Self::Profile { .. } | Self::Sso { .. } | Self::AssumeRole { .. } => {}
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Chain => Ok(()),
            Self::Static { access_key_id, .. } => {
                validate_required("AWS access key id", access_key_id)
            }
            Self::Profile { profile_name } => validate_required("AWS profile name", profile_name),
            Self::Sso { profile_name } => {
                validate_optional_non_empty("AWS SSO profile name", profile_name.as_deref())
            }
            Self::WebIdentity {
                role_arn,
                session_name,
            } => {
                validate_required("AWS role ARN", role_arn)?;
                validate_optional_non_empty("AWS role session name", session_name.as_deref())
            }
            Self::AssumeRole {
                role_arn,
                source_profile,
                session_name,
                ..
            } => {
                validate_required("AWS role ARN", role_arn)?;
                validate_optional_non_empty("AWS source profile", source_profile.as_deref())?;
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
pub enum PortableGcpAuthSource {
    Adc,
    ServiceAccountJson,
    Impersonation {
        target_principal: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        delegates: Vec<String>,
    },
    WorkloadIdentity {
        audience: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        service_account_impersonation_url: Option<String>,
    },
}

impl PortableGcpAuthSource {
    fn from_source(source: &GcpAuthSource) -> Self {
        match source {
            GcpAuthSource::Adc => Self::Adc,
            GcpAuthSource::ServiceAccountJson { .. } => Self::ServiceAccountJson,
            GcpAuthSource::Impersonation {
                target_principal,
                delegates,
            } => Self::Impersonation {
                target_principal: target_principal.clone(),
                delegates: delegates.clone(),
            },
            GcpAuthSource::WorkloadIdentity {
                audience,
                service_account_impersonation_url,
                ..
            } => Self::WorkloadIdentity {
                audience: audience.clone(),
                service_account_impersonation_url: service_account_impersonation_url.clone(),
            },
        }
    }

    fn append_secret_slots(&self, profile_id: &str, path: &str, slots: &mut Vec<SecretSlot>) {
        match self {
            Self::ServiceAccountJson => slots.push(SecretSlot::new(
                profile_id,
                format!("{path}.credentials"),
                SecretSlotPurpose::GcpServiceAccountJson,
            )),
            Self::WorkloadIdentity { .. } => slots.push(SecretSlot::new(
                profile_id,
                format!("{path}.subjectToken"),
                SecretSlotPurpose::GcpSubjectToken,
            )),
            Self::Adc | Self::Impersonation { .. } => {}
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Adc | Self::ServiceAccountJson => Ok(()),
            Self::Impersonation {
                target_principal,
                delegates,
            } => {
                validate_required("GCP target principal", target_principal)?;
                validate_string_list("GCP delegate", delegates)
            }
            Self::WorkloadIdentity {
                audience,
                service_account_impersonation_url,
            } => {
                validate_required("GCP workload identity audience", audience)?;
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
pub enum PortableAzureAuthSource {
    Cli,
    ManagedIdentity {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        client_id: Option<String>,
    },
    ServicePrincipal {
        tenant_id: String,
        client_id: String,
    },
    ServicePrincipalCertificate {
        tenant_id: String,
        client_id: String,
        passphrase_required: bool,
    },
}

impl PortableAzureAuthSource {
    fn from_source(source: &AzureAuthSource) -> Self {
        match source {
            AzureAuthSource::Cli => Self::Cli,
            AzureAuthSource::ManagedIdentity { client_id } => Self::ManagedIdentity {
                client_id: client_id.clone(),
            },
            AzureAuthSource::ServicePrincipal {
                tenant_id,
                client_id,
                ..
            } => Self::ServicePrincipal {
                tenant_id: tenant_id.clone(),
                client_id: client_id.clone(),
            },
            AzureAuthSource::ServicePrincipalCertificate {
                tenant_id,
                client_id,
                passphrase,
                ..
            } => Self::ServicePrincipalCertificate {
                tenant_id: tenant_id.clone(),
                client_id: client_id.clone(),
                passphrase_required: passphrase.is_some(),
            },
        }
    }

    fn append_secret_slots(&self, profile_id: &str, path: &str, slots: &mut Vec<SecretSlot>) {
        match self {
            Self::ServicePrincipal { .. } => slots.push(SecretSlot::new(
                profile_id,
                format!("{path}.clientSecret"),
                SecretSlotPurpose::AzureClientSecret,
            )),
            Self::ServicePrincipalCertificate {
                passphrase_required,
                ..
            } => {
                slots.push(SecretSlot::new(
                    profile_id,
                    format!("{path}.certificate"),
                    SecretSlotPurpose::AzureClientCertificate,
                ));
                slots.push(SecretSlot::new(
                    profile_id,
                    format!("{path}.privateKey"),
                    SecretSlotPurpose::AzurePrivateKey,
                ));
                if *passphrase_required {
                    slots.push(SecretSlot::new(
                        profile_id,
                        format!("{path}.passphrase"),
                        SecretSlotPurpose::AzureCertificatePassphrase,
                    ));
                }
            }
            Self::Cli | Self::ManagedIdentity { .. } => {}
        }
    }

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
            }
            | Self::ServicePrincipalCertificate {
                tenant_id,
                client_id,
                ..
            } => {
                validate_required("Azure tenant id", tenant_id)?;
                validate_required("Azure client id", client_id)
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
pub enum PortableAuthConfig {
    #[default]
    None,
    #[serde(alias = "secretRequired")]
    PasswordRequired,
    TokenRequired,
    ApiKeyRequired,
    #[serde(alias = "keyPairRequired")]
    KeyPairJwtRequired {
        #[serde(alias = "passphrase_required")]
        passphrase_required: bool,
        #[serde(default)]
        algorithm: JwtAlgorithm,
    },
    ClientCertificateRequired {
        passphrase_required: bool,
    },
    Kerberos {
        principal: String,
        service_name: String,
    },
    #[serde(rename = "oauth2")]
    #[ts(rename = "oauth2")]
    OAuth2 {
        flow: OAuth2Flow,
        client_id: String,
        client_secret_required: bool,
        refresh_token_required: bool,
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
        source: PortableAwsAuthSource,
    },
    Gcp {
        source: PortableGcpAuthSource,
    },
    Azure {
        source: PortableAzureAuthSource,
    },
}

impl PortableAuthConfig {
    fn from_auth(auth: &AuthConfig) -> Self {
        match auth {
            AuthConfig::None => Self::None,
            AuthConfig::Password { .. } => Self::PasswordRequired,
            AuthConfig::Token { .. } => Self::TokenRequired,
            AuthConfig::ApiKey { .. } => Self::ApiKeyRequired,
            AuthConfig::KeyPairJwt {
                passphrase,
                algorithm,
                ..
            } => Self::KeyPairJwtRequired {
                passphrase_required: passphrase.is_some(),
                algorithm: *algorithm,
            },
            AuthConfig::ClientCertificate { passphrase, .. } => Self::ClientCertificateRequired {
                passphrase_required: passphrase.is_some(),
            },
            AuthConfig::Kerberos {
                principal,
                service_name,
                ..
            } => Self::Kerberos {
                principal: principal.clone(),
                service_name: service_name.clone(),
            },
            AuthConfig::OAuth2 {
                flow,
                client_id,
                client_secret,
                refresh_token,
                token_endpoint,
                scopes,
            } => Self::OAuth2 {
                flow: *flow,
                client_id: client_id.clone(),
                client_secret_required: client_secret.is_some(),
                refresh_token_required: refresh_token.is_some(),
                token_endpoint: token_endpoint.clone(),
                scopes: scopes.clone(),
            },
            AuthConfig::ExternalBrowser {
                authorize_endpoint,
                redirect_port,
            } => Self::ExternalBrowser {
                authorize_endpoint: authorize_endpoint.clone(),
                redirect_port: *redirect_port,
            },
            AuthConfig::Aws { source } => Self::Aws {
                source: PortableAwsAuthSource::from_source(source),
            },
            AuthConfig::Gcp { source } => Self::Gcp {
                source: PortableGcpAuthSource::from_source(source),
            },
            AuthConfig::Azure { source } => Self::Azure {
                source: PortableAzureAuthSource::from_source(source),
            },
        }
    }

    fn append_secret_slots(&self, profile_id: &str, path: &str, slots: &mut Vec<SecretSlot>) {
        match self {
            Self::None | Self::ExternalBrowser { .. } => {}
            Self::PasswordRequired => slots.push(SecretSlot::new(
                profile_id,
                format!("{path}.password"),
                SecretSlotPurpose::Password,
            )),
            Self::TokenRequired => slots.push(SecretSlot::new(
                profile_id,
                format!("{path}.token"),
                SecretSlotPurpose::Token,
            )),
            Self::ApiKeyRequired => slots.push(SecretSlot::new(
                profile_id,
                format!("{path}.apiKey"),
                SecretSlotPurpose::ApiKey,
            )),
            Self::KeyPairJwtRequired {
                passphrase_required,
                ..
            } => {
                slots.push(SecretSlot::new(
                    profile_id,
                    format!("{path}.privateKey"),
                    SecretSlotPurpose::PrivateKey,
                ));
                if *passphrase_required {
                    slots.push(SecretSlot::new(
                        profile_id,
                        format!("{path}.passphrase"),
                        SecretSlotPurpose::Passphrase,
                    ));
                }
            }
            Self::ClientCertificateRequired {
                passphrase_required,
            } => {
                slots.push(SecretSlot::new(
                    profile_id,
                    format!("{path}.cert"),
                    SecretSlotPurpose::ClientCertificate,
                ));
                slots.push(SecretSlot::new(
                    profile_id,
                    format!("{path}.key"),
                    SecretSlotPurpose::ClientKey,
                ));
                if *passphrase_required {
                    slots.push(SecretSlot::new(
                        profile_id,
                        format!("{path}.passphrase"),
                        SecretSlotPurpose::ClientCertificatePassphrase,
                    ));
                }
            }
            Self::Kerberos { .. } => slots.push(SecretSlot::new(
                profile_id,
                format!("{path}.keytab"),
                SecretSlotPurpose::KerberosKeytab,
            )),
            Self::OAuth2 {
                client_secret_required,
                refresh_token_required,
                ..
            } => {
                if *client_secret_required {
                    slots.push(SecretSlot::new(
                        profile_id,
                        format!("{path}.clientSecret"),
                        SecretSlotPurpose::OAuthClientSecret,
                    ));
                }
                if *refresh_token_required {
                    slots.push(SecretSlot::new(
                        profile_id,
                        format!("{path}.refreshToken"),
                        SecretSlotPurpose::OAuthRefreshToken,
                    ));
                }
            }
            Self::Aws { source } => {
                source.append_secret_slots(profile_id, &format!("{path}.source"), slots);
            }
            Self::Gcp { source } => {
                source.append_secret_slots(profile_id, &format!("{path}.source"), slots);
            }
            Self::Azure { source } => {
                source.append_secret_slots(profile_id, &format!("{path}.source"), slots);
            }
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::None
            | Self::PasswordRequired
            | Self::TokenRequired
            | Self::ApiKeyRequired
            | Self::KeyPairJwtRequired { .. }
            | Self::ClientCertificateRequired { .. } => Ok(()),
            Self::Kerberos {
                principal,
                service_name,
            } => {
                validate_required("Kerberos principal", principal)?;
                validate_required("Kerberos service name", service_name)
            }
            Self::OAuth2 {
                flow,
                client_id,
                client_secret_required,
                refresh_token_required,
                token_endpoint,
                scopes,
            } => {
                validate_required("OAuth2 client id", client_id)?;
                if *flow == OAuth2Flow::ClientCredentials && !client_secret_required {
                    return Err(IrodoriError::validation(
                        "portable OAuth2 client-credentials flow requires a client-secret slot",
                    ));
                }
                if *flow == OAuth2Flow::RefreshToken && !refresh_token_required {
                    return Err(IrodoriError::validation(
                        "portable OAuth2 refresh-token flow requires a refresh-token slot",
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
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct PortableTlsConfig {
    #[serde(default)]
    pub mode: TlsMode,
    #[serde(default)]
    pub root_cert_required: bool,
    #[serde(default)]
    pub client_cert_required: bool,
    #[serde(default)]
    pub client_key_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub server_name: Option<String>,
}

impl PortableTlsConfig {
    fn from_tls(tls: &TlsConfig) -> Self {
        Self {
            mode: tls.mode,
            root_cert_required: tls.root_cert.is_some(),
            client_cert_required: tls.client_cert.is_some(),
            client_key_required: tls.client_key.is_some(),
            server_name: tls.server_name.clone(),
        }
    }

    fn append_secret_slots(&self, profile_id: &str, path: &str, slots: &mut Vec<SecretSlot>) {
        if self.root_cert_required {
            slots.push(SecretSlot::new(
                profile_id,
                format!("{path}.rootCert"),
                SecretSlotPurpose::TlsRootCertificate,
            ));
        }
        if self.client_cert_required {
            slots.push(SecretSlot::new(
                profile_id,
                format!("{path}.clientCert"),
                SecretSlotPurpose::TlsClientCertificate,
            ));
        }
        if self.client_key_required {
            slots.push(SecretSlot::new(
                profile_id,
                format!("{path}.clientKey"),
                SecretSlotPurpose::TlsClientKey,
            ));
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_optional_non_empty("TLS server name", self.server_name.as_deref())?;
        if self.client_cert_required != self.client_key_required {
            return Err(IrodoriError::validation(
                "portable TLS client certificate and client key must be required together",
            ));
        }
        if self.mode == TlsMode::ClientCertificate && !self.client_cert_required {
            return Err(IrodoriError::validation(
                "portable client-certificate TLS mode requires a client certificate and key",
            ));
        }
        if matches!(self.mode, TlsMode::Default | TlsMode::Disable)
            && (self.root_cert_required
                || self.client_cert_required
                || self.client_key_required
                || self.server_name.is_some())
        {
            return Err(IrodoriError::validation(
                "portable TLS certificate and server-name options require an explicit enabled mode",
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
pub struct SecretSlot {
    pub profile_id: String,
    pub path: String,
    pub purpose: SecretSlotPurpose,
}

impl SecretSlot {
    fn new(
        profile_id: impl Into<String>,
        path: impl Into<String>,
        purpose: SecretSlotPurpose,
    ) -> Self {
        Self {
            profile_id: profile_id.into(),
            path: path.into(),
            purpose,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum SecretSlotPurpose {
    Password,
    Token,
    ApiKey,
    PrivateKey,
    Passphrase,
    ClientCertificate,
    ClientKey,
    ClientCertificatePassphrase,
    KerberosKeytab,
    OAuthClientSecret,
    OAuthRefreshToken,
    AwsSecretAccessKey,
    AwsSessionToken,
    AwsWebIdentityToken,
    AwsExternalId,
    GcpServiceAccountJson,
    GcpSubjectToken,
    AzureClientSecret,
    AzureClientCertificate,
    AzurePrivateKey,
    AzureCertificatePassphrase,
    TlsRootCertificate,
    TlsClientCertificate,
    TlsClientKey,
    SshPassword,
    ProxyPassword,
}
