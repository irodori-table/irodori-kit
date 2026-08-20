use super::*;
use serde_json::json;

fn valid_profile() -> ConnectionProfile {
    ConnectionProfile {
        id: "local-postgres".to_string(),
        display_name: "Local Postgres".to_string(),
        source: SourceKind::postgresql(),
        transport: TransportConfig::Direct(DirectTransport {
            host: "localhost".to_string(),
            port: Some(5432),
            tls: true,
        }),
        database: Some("app".to_string()),
        user: Some("irodori".to_string()),
        auth: AuthConfig::Password {
            password: SecretRef::new("keychain:local-postgres/password"),
        },
        tls: TlsConfig::default(),
        options: BTreeMap::from([("applicationName".to_string(), "irodori".to_string())]),
    }
}

#[test]
fn valid_connection_profile_passes_validation() {
    assert!(valid_profile().validate().is_ok());
}

#[test]
fn invalid_required_fields_fail_validation() {
    let mut profile = valid_profile();
    profile.id = " ".to_string();
    assert!(profile.validate().is_err());

    let mut profile = valid_profile();
    profile.display_name = " ".to_string();
    assert!(profile.validate().is_err());

    let mut profile = valid_profile();
    profile.source.id.clear();
    assert!(profile.validate().is_err());

    let mut profile = valid_profile();
    profile.transport = TransportConfig::Direct(DirectTransport::new(" ", Some(5432)));
    assert!(profile.validate().is_err());

    let mut profile = valid_profile();
    profile.transport = TransportConfig::Direct(DirectTransport::new("localhost", Some(0)));
    assert!(profile.validate().is_err());
}

#[test]
fn connection_profile_serializes_with_camel_case_fields() {
    assert_eq!(
        serde_json::to_value(valid_profile()).unwrap(),
        json!({
            "id": "local-postgres",
            "displayName": "Local Postgres",
            "source": {
                "id": "postgresql",
                "family": "sql"
            },
            "transport": {
                "kind": "direct",
                "host": "localhost",
                "port": 5432,
                "tls": true
            },
            "database": "app",
            "user": "irodori",
            "auth": {
                "kind": "password",
                "password": {
                    "handle": "keychain:local-postgres/password"
                }
            },
            "options": {
                "applicationName": "irodori"
            }
        })
    );
}

#[test]
fn desktop_connection_profile_keeps_app_compatible_shape() {
    let profile = DesktopConnectionProfile {
        id: "local-postgres".to_string(),
        engine: "postgres".to_string(),
        host: Some("127.0.0.1".to_string()),
        port: Some(5432),
        user: Some("irodori".to_string()),
        password: None,
        auth: AuthConfig::None,
        tls: TlsConfig::default(),
        database: Some("samples".to_string()),
        socket_path: Some("/var/run/postgresql".to_string()),
        url: None,
        transport: Some(TransportConfig::LocalFile(LocalFileTransport {
            path: "/var/run/postgresql".to_string(),
        })),
        read_only: true,
        options: BTreeMap::from([("applicationName".to_string(), "irodori".to_string())]),
    };

    assert_eq!(
        serde_json::to_value(profile).unwrap(),
        json!({
            "id": "local-postgres",
            "engine": "postgres",
            "host": "127.0.0.1",
            "port": 5432,
            "user": "irodori",
            "database": "samples",
            "socketPath": "/var/run/postgresql",
            "transport": {
                "kind": "localFile",
                "path": "/var/run/postgresql"
            },
            "readOnly": true,
            "options": {
                "applicationName": "irodori"
            }
        })
    );
}

#[test]
fn secret_material_is_not_part_of_the_profile_shape() {
    let mut profile = valid_profile();
    profile
        .options
        .insert("password".to_string(), "supersecret".to_string());

    assert!(profile.validate().is_err());

    let mut profile = valid_profile();
    profile
        .options
        .insert("apiKey".to_string(), "supersecret".to_string());
    assert!(profile.validate().is_err());

    let serialized = serde_json::to_string(&valid_profile()).unwrap();
    assert!(!serialized.contains("supersecret"));
    assert!(!serialized.contains("\"password\":\"supersecret\""));
}

#[test]
fn connection_profile_export_has_schema_version_and_excludes_secret_handles() {
    let mut profile = valid_profile();
    profile.transport = TransportConfig::SshTunnel(SshTunnelTransport {
        auth: SshAuthConfig::Password {
            password: SecretRef::new("keychain:ssh/supersecret"),
        },
        ..SshTunnelTransport::new("bastion.internal", "deploy", "db.internal", 5432)
    });

    let export = ConnectionProfileExport::from_profiles([&profile]).unwrap();
    assert_eq!(export.schema_version, CONNECTION_PROFILE_SCHEMA_VERSION);
    assert_eq!(
        export.profiles[0].auth,
        PortableAuthConfig::PasswordRequired
    );

    let serialized = serde_json::to_string(&export).unwrap();
    assert!(serialized.contains("\"schemaVersion\":2"));
    assert!(serialized.contains("\"passwordRequired\""));
    assert!(serialized.contains("\"passwordRequired\""));
    assert!(!serialized.contains("keychain:"));
    assert!(!serialized.contains("supersecret"));
    assert!(!serialized.contains("local-postgres/password"));
}

#[test]
fn portable_profile_reports_secret_slots_for_import_relinking() {
    let mut profile = valid_profile();
    profile.transport = TransportConfig::SshTunnel(SshTunnelTransport {
        auth: SshAuthConfig::Password {
            password: SecretRef::new("keychain:ssh/password"),
        },
        ..SshTunnelTransport::new("bastion.internal", "deploy", "db.internal", 5432)
    });

    let portable = PortableConnectionProfile::from_profile(&profile);
    assert_eq!(
        portable.required_secret_slots(),
        vec![
            SecretSlot {
                profile_id: "local-postgres".to_string(),
                path: "auth.password".to_string(),
                purpose: SecretSlotPurpose::Password,
            },
            SecretSlot {
                profile_id: "local-postgres".to_string(),
                path: "transport.ssh.password".to_string(),
                purpose: SecretSlotPurpose::SshPassword,
            },
        ]
    );
}

#[test]
fn portable_cloud_auth_and_tls_report_every_secret_slot() {
    let mut profile = valid_profile();
    profile.auth = AuthConfig::Aws {
        source: AwsAuthSource::Static {
            access_key_id: "AKIAEXAMPLE".to_string(),
            secret_access_key: SecretRef::new("keychain:aws/secret-access-key"),
            session_token: Some(SecretRef::new("keychain:aws/session-token")),
        },
    };
    profile.tls = TlsConfig {
        mode: TlsMode::VerifyFull,
        root_cert: Some(SecretRef::new("keychain:tls/root-cert")),
        client_cert: Some(SecretRef::new("keychain:tls/client-cert")),
        client_key: Some(SecretRef::new("keychain:tls/client-key")),
        server_name: Some("db.internal".to_string()),
    };

    let portable = PortableConnectionProfile::from_profile(&profile);
    assert_eq!(
        portable.required_secret_slots(),
        vec![
            SecretSlot {
                profile_id: "local-postgres".to_string(),
                path: "auth.source.secretAccessKey".to_string(),
                purpose: SecretSlotPurpose::AwsSecretAccessKey,
            },
            SecretSlot {
                profile_id: "local-postgres".to_string(),
                path: "auth.source.sessionToken".to_string(),
                purpose: SecretSlotPurpose::AwsSessionToken,
            },
            SecretSlot {
                profile_id: "local-postgres".to_string(),
                path: "tls.rootCert".to_string(),
                purpose: SecretSlotPurpose::TlsRootCertificate,
            },
            SecretSlot {
                profile_id: "local-postgres".to_string(),
                path: "tls.clientCert".to_string(),
                purpose: SecretSlotPurpose::TlsClientCertificate,
            },
            SecretSlot {
                profile_id: "local-postgres".to_string(),
                path: "tls.clientKey".to_string(),
                purpose: SecretSlotPurpose::TlsClientKey,
            },
        ]
    );

    let serialized = serde_json::to_string(&portable).unwrap();
    assert!(!serialized.contains("keychain:"));
    assert!(serialized.contains("AKIAEXAMPLE"));
}

#[test]
fn every_typed_auth_family_validates_and_exports_without_secret_handles() {
    let secret = |name: &str| SecretRef::new(format!("keychain:test/{name}"));
    let variants = vec![
        AuthConfig::Password {
            password: secret("password"),
        },
        AuthConfig::Token {
            token: secret("token"),
        },
        AuthConfig::ApiKey {
            api_key: secret("api-key"),
        },
        AuthConfig::KeyPairJwt {
            private_key: secret("jwt-key"),
            passphrase: Some(secret("jwt-passphrase")),
            algorithm: JwtAlgorithm::Es256,
        },
        AuthConfig::ClientCertificate {
            cert: secret("certificate"),
            key: secret("certificate-key"),
            passphrase: Some(secret("certificate-passphrase")),
        },
        AuthConfig::Kerberos {
            principal: "user@EXAMPLE.COM".to_string(),
            keytab: secret("keytab"),
            service_name: "postgres".to_string(),
        },
        AuthConfig::OAuth2 {
            flow: OAuth2Flow::ClientCredentials,
            client_id: "irodori".to_string(),
            client_secret: Some(secret("oauth-client-secret")),
            refresh_token: None,
            token_endpoint: "https://id.example.test/token".to_string(),
            scopes: vec!["database.read".to_string()],
        },
        AuthConfig::ExternalBrowser {
            authorize_endpoint: "https://id.example.test/authorize".to_string(),
            redirect_port: Some(8400),
        },
        AuthConfig::Aws {
            source: AwsAuthSource::AssumeRole {
                role_arn: "arn:aws:iam::123456789012:role/database".to_string(),
                source_profile: Some("default".to_string()),
                external_id: Some(secret("aws-external-id")),
                session_name: Some("irodori".to_string()),
            },
        },
        AuthConfig::Gcp {
            source: GcpAuthSource::WorkloadIdentity {
                audience: "//iam.googleapis.com/projects/example".to_string(),
                subject_token: secret("gcp-subject-token"),
                service_account_impersonation_url: None,
            },
        },
        AuthConfig::Azure {
            source: AzureAuthSource::ServicePrincipalCertificate {
                tenant_id: "tenant".to_string(),
                client_id: "client".to_string(),
                certificate: secret("azure-certificate"),
                private_key: secret("azure-private-key"),
                passphrase: Some(secret("azure-passphrase")),
            },
        },
    ];

    for (index, auth) in variants.into_iter().enumerate() {
        let mut profile = valid_profile();
        profile.id = format!("typed-auth-{index}");
        profile.auth = auth;
        let export = ConnectionProfileExport::from_profiles([&profile]).unwrap();
        let serialized = serde_json::to_string(&export).unwrap();
        assert!(!serialized.contains("keychain:"), "{serialized}");
    }
}

#[test]
fn oauth_flows_require_their_secrets_and_secure_endpoints() {
    let mut profile = valid_profile();
    profile.auth = AuthConfig::OAuth2 {
        flow: OAuth2Flow::ClientCredentials,
        client_id: "irodori".to_string(),
        client_secret: None,
        refresh_token: None,
        token_endpoint: "https://id.example.test/token".to_string(),
        scopes: Vec::new(),
    };
    assert!(profile
        .validate()
        .unwrap_err()
        .message
        .contains("requires a client secret"));

    profile.auth = AuthConfig::OAuth2 {
        flow: OAuth2Flow::ClientCredentials,
        client_id: "irodori".to_string(),
        client_secret: Some(SecretRef::new("keychain:oauth/client-secret")),
        refresh_token: None,
        token_endpoint: "http://id.example.test/token".to_string(),
        scopes: Vec::new(),
    };
    assert!(profile
        .validate()
        .unwrap_err()
        .message
        .contains("must use HTTPS"));
}

#[test]
fn connection_profile_export_rejects_unsupported_schema_versions() {
    let export = ConnectionProfileExport {
        schema_version: CONNECTION_PROFILE_SCHEMA_VERSION + 1,
        profiles: Vec::new(),
    };

    let error = export.validate_schema_version().unwrap_err();
    assert_eq!(error.kind, irodori_error::IrodoriErrorKind::Validation);
    assert!(error.message.contains("schema version"));
}

#[test]
fn connection_profile_export_accepts_legacy_schema_version() {
    let export = ConnectionProfileExport {
        schema_version: 1,
        profiles: Vec::new(),
    };

    assert!(export.validate_schema_version().is_ok());
}

#[test]
fn connection_profile_export_rejects_duplicate_profile_ids() {
    let first = valid_profile();
    let mut second = valid_profile();
    second.display_name = "Duplicate".to_string();

    let error = ConnectionProfileExport::from_profiles([&first, &second]).unwrap_err();
    assert!(error.message.contains("duplicated"));
}

#[test]
fn portable_tls_validation_rejects_missing_client_key_slot() {
    let mut portable = PortableConnectionProfile::from_profile(&valid_profile());
    portable.tls = PortableTlsConfig {
        mode: TlsMode::ClientCertificate,
        client_cert_required: true,
        client_key_required: false,
        ..PortableTlsConfig::default()
    };
    let export = ConnectionProfileExport {
        schema_version: CONNECTION_PROFILE_SCHEMA_VERSION,
        profiles: vec![portable],
    };

    let error = export.validate().unwrap_err();
    assert!(error.message.contains("required together"));
}

#[test]
fn unknown_password_field_is_rejected_on_deserialize() {
    let value = json!({
        "id": "local-postgres",
        "displayName": "Local Postgres",
        "source": {
            "id": "postgresql",
            "family": "sql"
        },
        "transport": {
            "kind": "direct",
            "host": "localhost",
            "port": 5432,
            "tls": true
        },
        "auth": {
            "kind": "none"
        },
        "options": {},
        "password": "supersecret"
    });

    assert!(serde_json::from_value::<ConnectionProfile>(value).is_err());
}

#[test]
fn legacy_auth_json_migrates_to_typed_variants() {
    let password = serde_json::from_value::<AuthConfig>(json!({
        "kind": "secret",
        "secret": { "handle": "keychain:legacy/password" }
    }))
    .unwrap();
    assert_eq!(
        password,
        AuthConfig::Password {
            password: SecretRef::new("keychain:legacy/password")
        }
    );

    let key_pair = serde_json::from_value::<AuthConfig>(json!({
        "kind": "keyPair",
        "privateKey": { "handle": "keychain:legacy/private-key" }
    }))
    .unwrap();
    assert_eq!(
        key_pair,
        AuthConfig::KeyPairJwt {
            private_key: SecretRef::new("keychain:legacy/private-key"),
            passphrase: None,
            algorithm: JwtAlgorithm::Rs256,
        }
    );

    let legacy_snake_case = serde_json::from_value::<AuthConfig>(json!({
        "kind": "keyPair",
        "private_key": { "handle": "keychain:legacy/private-key" }
    }))
    .unwrap();
    assert_eq!(legacy_snake_case, key_pair);

    let canonical = serde_json::to_value(key_pair).unwrap();
    assert!(canonical.get("privateKey").is_some());
    assert!(canonical.get("private_key").is_none());
}

#[test]
fn legacy_portable_auth_json_remains_importable() {
    assert_eq!(
        serde_json::from_value::<PortableAuthConfig>(json!({
            "kind": "secretRequired"
        }))
        .unwrap(),
        PortableAuthConfig::PasswordRequired,
    );
    assert_eq!(
        serde_json::from_value::<PortableAuthConfig>(json!({
            "kind": "keyPairRequired",
            "passphrase_required": true
        }))
        .unwrap(),
        PortableAuthConfig::KeyPairJwtRequired {
            passphrase_required: true,
            algorithm: JwtAlgorithm::Rs256,
        },
    );
}

#[test]
fn desktop_legacy_password_is_deserialize_only() {
    let profile = serde_json::from_value::<DesktopConnectionProfile<String>>(json!({
        "id": "legacy",
        "engine": "postgres",
        "password": "supersecret"
    }))
    .unwrap();
    assert_eq!(profile.password.as_deref(), Some("supersecret"));
    assert_eq!(profile.auth, AuthConfig::None);
    assert_eq!(profile.tls, TlsConfig::default());

    let error = serde_json::to_string(&profile).unwrap_err();
    assert!(error.to_string().contains("must be migrated"));

    let mut migrated = profile;
    let plaintext = migrated.password.take();
    migrated.auth = AuthConfig::Password {
        password: SecretRef::new("keychain:legacy/password"),
    };
    assert_eq!(plaintext.as_deref(), Some("supersecret"));
    let serialized = serde_json::to_string(&migrated).unwrap();
    assert!(!serialized.contains("supersecret"));
}

#[test]
fn typed_tls_rejects_incomplete_client_credentials() {
    let mut profile = valid_profile();
    profile.tls = TlsConfig {
        mode: TlsMode::VerifyFull,
        client_cert: Some(SecretRef::new("keychain:tls/client-cert")),
        server_name: Some("db.internal".to_string()),
        ..TlsConfig::default()
    };

    let error = profile.validate().unwrap_err();
    assert!(error.message.contains("configured together"));
}

#[test]
fn ssh_tunnel_supports_agent_password_and_key_auth_refs() {
    let agent = TransportConfig::SshTunnel(SshTunnelTransport::new(
        "bastion.internal",
        "deploy",
        "db.internal",
        5432,
    ));
    assert!(agent.validate().is_ok());

    let password = TransportConfig::SshTunnel(SshTunnelTransport {
        auth: SshAuthConfig::Password {
            password: SecretRef::new("keychain:conn/ssh-password"),
        },
        ..SshTunnelTransport::new("bastion.internal", "deploy", "db.internal", 5432)
    });
    assert!(password.validate().is_ok());

    let private_key = TransportConfig::SshTunnel(SshTunnelTransport {
        auth: SshAuthConfig::PrivateKey {
            private_key: SecretRef::new("keychain:conn/private-key"),
            passphrase: Some(SecretRef::new("keychain:conn/private-key-passphrase")),
        },
        ..SshTunnelTransport::new("bastion.internal", "deploy", "db.internal", 5432)
    });
    assert!(private_key.validate().is_ok());
}

#[test]
fn proxy_chain_requires_named_unique_valid_hops() {
    let chain = TransportConfig::Chain(ProxyChainTransport::new(
        "db.internal",
        5432,
        vec![
            ProxyChainHop::new(
                "corp-bastion",
                ProxyHopConfig::Ssh(SshProxyHop::new("bastion.internal", "deploy")),
            ),
            ProxyChainHop::new(
                "region-socks",
                ProxyHopConfig::Socks5(ProxyTransport {
                    auth: Some(ProxyAuthConfig {
                        username: "proxy-user".to_string(),
                        password: SecretRef::new("keychain:proxy/password"),
                    }),
                    ..ProxyTransport::new("socks.internal", 1080)
                }),
            ),
        ],
    ));
    assert!(chain.validate().is_ok());

    let duplicate = TransportConfig::Chain(ProxyChainTransport::new(
        "db.internal",
        5432,
        vec![
            ProxyChainHop::new(
                "same",
                ProxyHopConfig::HttpConnect(ProxyTransport::new("proxy-a.internal", 8080)),
            ),
            ProxyChainHop::new(
                "same",
                ProxyHopConfig::HttpConnect(ProxyTransport::new("proxy-b.internal", 8080)),
            ),
        ],
    ));
    let error = duplicate.validate().unwrap_err();
    assert!(error.message.contains("duplicated"));

    let too_short = TransportConfig::Chain(ProxyChainTransport::new(
        "db.internal",
        5432,
        vec![ProxyChainHop::new(
            "only-hop",
            ProxyHopConfig::Socks5(ProxyTransport::new("socks.internal", 1080)),
        )],
    ));
    let error = too_short.validate().unwrap_err();
    assert!(error.message.contains("at least two"));
}
