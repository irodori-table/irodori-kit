//! Core workspace, command, and shared domain types for Irodori Table.
//!
//! The error vocabulary and command envelope now live in `irodori-error`, and
//! the job/batch runtime lives in `irodori-jobs`; they are re-exported here so existing
//! `irodori_core::{IrodoriError, JobKind, ...}` paths keep working.

pub use irodori_connection::{
    AuthConfig, ConnectionProfile, ConnectionProfileExport, DirectTransport, LocalFileTransport,
    PortableAuthConfig, PortableConnectionProfile, PortableProxyAuthConfig, PortableProxyChainHop,
    PortableProxyChainTransport, PortableProxyHopConfig, PortableProxyTransport,
    PortableSshAuthConfig, PortableSshProxyHop, PortableSshTunnelTransport,
    PortableTransportConfig, ProxyAuthConfig, ProxyChainHop, ProxyChainTransport, ProxyHopConfig,
    ProxyTransport, SecretRef, SecretSlot, SecretSlotPurpose, SourceFamily, SourceKind,
    SshAuthConfig, SshProxyHop, SshTunnelTransport, TransportConfig,
    CONNECTION_PROFILE_SCHEMA_VERSION,
};
pub use irodori_error::{CommandResult, IrodoriError, IrodoriErrorKind, Result};
pub use irodori_jobs::{
    run_job, BatchOutcome, BatchResult, JobArtifact, JobCheckpoint, JobConcurrencyPolicy,
    JobContext, JobKind, JobList, JobLogEntry, JobLogLevel, JobProgress, JobRecord,
    JobResourceBudget, JobRetryPolicy, JobRuntime, JobRuntimeConfig, JobSpec, JobStatus,
    JobSummary,
};
pub use irodori_security::{
    AuditEvent, AuditEventKind, AuditLog, PrivacyMode, RedactedExport, RedactionReport, Redactor,
};

pub const CRATE_NAME: &str = "irodori-core";

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn command_result_envelope_serializes_success_and_failure() {
        assert_eq!(
            serde_json::to_value(CommandResult::success(42_u32)).unwrap(),
            json!({
                "ok": true,
                "data": 42
            })
        );

        assert_eq!(
            serde_json::to_value(CommandResult::<u32>::failure(IrodoriError::validation(
                "connection id is required"
            )))
            .unwrap(),
            json!({
                "ok": false,
                "error": {
                    "kind": "validation",
                    "message": "connection id is required",
                    "retryable": false
                }
            })
        );
    }
}
