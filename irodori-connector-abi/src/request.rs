//! Reading configuration out of a connect request.
//!
//! Every connector needs the same four things: find a field wherever the host
//! put it, collect secrets for redaction, strip credentials out of a URL before
//! logging it, and know which containers to look in. Each one had been copied
//! into every connector — `option_string` into all 35, `request_containers`
//! into 33 — and the copies had drifted into four different behaviours, so the
//! same profile could resolve differently depending on which connector read it.
//!
//! The drift was not cosmetic. Two connectors searched fewer containers than
//! the rest and silently could not see a credential supplied under `auth`; two
//! more read only strings, so a port given as a JSON number was invisible.

use serde_json::Value;

/// Every place the host may put a connection setting, in priority order.
///
/// The order matters: the request itself and its `profile` win over the
/// `options`/`auth`/`secrets` maps, so an explicit profile field beats a
/// leftover option of the same name.
pub fn request_containers(request: &Value) -> Vec<&Value> {
    [
        Some(request),
        request.get("profile"),
        request.get("options"),
        request.get("auth"),
        request.get("secrets"),
        request.get("profile").and_then(|p| p.get("options")),
        request.get("profile").and_then(|p| p.get("auth")),
        request.get("profile").and_then(|p| p.get("secrets")),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// The first of `fields` present anywhere in the request, as a trimmed string.
///
/// Numbers and booleans are accepted and stringified: a port or a flag arrives
/// as a JSON number or bool depending on how the profile was written, and a
/// connector that only read strings saw neither.
///
/// An object is unwrapped when it looks like a wrapped value — the host may
/// deliver a secret as `{"value": "…"}` rather than a bare string.
pub fn option_string(request: &Value, fields: &[&str]) -> Option<String> {
    request_containers(request)
        .into_iter()
        .find_map(|container| {
            fields
                .iter()
                .find_map(|field| container.get(*field).and_then(scalar_string))
        })
}

/// The same lookup as [`option_string`], as a boolean.
///
/// Accepts the JSON literal and the spellings a text field produces, because a
/// connection form has no way to submit a real boolean.
pub fn option_bool(request: &Value, fields: &[&str]) -> Option<bool> {
    option_string(request, fields).and_then(|value| {
        match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        }
    })
}

fn scalar_string(value: &Value) -> Option<String> {
    let text = match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        // A wrapped value: `{"value": "…"}`, `{"secret": "…"}`, and the
        // variants the host uses for secret handles and endpoints.
        Value::Object(object) => [
            "value",
            "secret",
            "token",
            "password",
            "apiKey",
            "accessToken",
            "url",
            "uri",
            "text",
        ]
        .iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(ToOwned::to_owned)?,
        _ => return None,
    };
    let text = text.trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// Record a value so it can be removed from anything the connector reports.
///
/// Empty values are refused: `str::replace` with an empty needle inserts the
/// replacement between every character, which turns an error message into
/// unreadable interleaved text. That bug shipped in one connector.
pub fn push_sensitive(values: &mut Vec<String>, value: Option<&str>) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        if !values.iter().any(|existing| existing == value) {
            values.push(value.to_string());
        }
    }
}

/// Add any credentials embedded in a URL's userinfo to the redaction list.
///
/// A password in a connection string reaches logs through error messages that
/// quote the URL, and a user who pasted a DSN has no idea it is in there.
pub fn collect_url_auth(url: &str, values: &mut Vec<String>) {
    let Some(after_scheme) = url.split_once("://").map(|(_, rest)| rest) else {
        return;
    };
    let Some(auth) = after_scheme
        .split('/')
        .next()
        .and_then(|host| host.rsplit_once('@').map(|(auth, _)| auth))
    else {
        return;
    };
    for part in auth.split(':') {
        push_sensitive(values, Some(part));
    }
}

/// Replace every recorded secret in `message`.
pub fn redact(message: &str, values: &[String]) -> String {
    values.iter().fold(message.to_string(), |message, secret| {
        if secret.is_empty() {
            message
        } else {
            message.replace(secret, "****")
        }
    })
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn searches_every_container_the_host_may_use() {
        // Two connectors omitted `auth` and could not see a credential
        // delivered there; nothing failed loudly, the field was simply absent.
        for container in ["options", "auth", "secrets"] {
            let request = json!({ "profile": { container: { "token": "found" } } });
            assert_eq!(
                option_string(&request, &["token"]).as_deref(),
                Some("found"),
                "profile.{container}"
            );
            let request = json!({ container: { "token": "found" } });
            assert_eq!(
                option_string(&request, &["token"]).as_deref(),
                Some("found"),
                "{container}"
            );
        }
    }

    #[test]
    fn a_profile_field_wins_over_an_option_of_the_same_name() {
        let request = json!({
            "profile": { "database": "explicit", "options": { "database": "stale" } }
        });
        assert_eq!(
            option_string(&request, &["database"]).as_deref(),
            Some("explicit")
        );
    }

    #[test]
    fn numbers_and_booleans_are_readable_as_text() {
        // A port arrives as a number or a string depending on how the profile
        // was written; connectors that read only strings saw neither.
        let request = json!({ "profile": { "port": 5432, "readOnly": true } });
        assert_eq!(option_string(&request, &["port"]).as_deref(), Some("5432"));
        assert_eq!(
            option_string(&request, &["readOnly"]).as_deref(),
            Some("true")
        );
    }

    #[test]
    fn a_wrapped_secret_is_unwrapped() {
        let request = json!({ "profile": { "secrets": { "token": { "value": "shh" } } } });
        assert_eq!(option_string(&request, &["token"]).as_deref(), Some("shh"));
    }

    #[test]
    fn blank_and_missing_are_both_absent() {
        let request = json!({ "profile": { "user": "   ", "password": null } });
        assert_eq!(option_string(&request, &["user"]), None);
        assert_eq!(option_string(&request, &["password"]), None);
        assert_eq!(option_string(&request, &["nothing"]), None);
    }

    #[test]
    fn the_first_matching_field_name_wins() {
        let request = json!({ "profile": { "options": { "b": "second" } } });
        assert_eq!(
            option_string(&request, &["a", "b"]).as_deref(),
            Some("second")
        );
    }

    #[test]
    fn booleans_accept_the_spellings_a_text_field_produces() {
        for (text, expected) in [
            ("true", true),
            ("Yes", true),
            ("1", true),
            ("false", false),
            ("off", false),
            ("0", false),
        ] {
            let request = json!({ "profile": { "options": { "flag": text } } });
            assert_eq!(option_bool(&request, &["flag"]), Some(expected), "{text}");
        }
        let request = json!({ "profile": { "options": { "flag": "maybe" } } });
        assert_eq!(option_bool(&request, &["flag"]), None);
    }

    #[test]
    fn an_empty_secret_is_never_recorded() {
        // Regression: `str::replace` with an empty needle inserts the
        // replacement between every character.
        let mut values = Vec::new();
        push_sensitive(&mut values, Some("   "));
        push_sensitive(&mut values, None);
        assert!(values.is_empty());
        assert_eq!(redact("login failed", &values), "login failed");
    }

    #[test]
    fn a_secret_is_recorded_once() {
        let mut values = Vec::new();
        push_sensitive(&mut values, Some("hunter2"));
        push_sensitive(&mut values, Some("hunter2"));
        assert_eq!(values, vec!["hunter2".to_string()]);
    }

    #[test]
    fn url_credentials_are_collected_for_redaction() {
        let mut values = Vec::new();
        collect_url_auth("postgres://user:hunter2@db.example:5432/app", &mut values);
        assert!(values.contains(&"hunter2".to_string()));
        assert_eq!(
            redact("connect failed for user:hunter2", &values),
            "connect failed for ****:****"
        );
    }

    #[test]
    fn a_password_containing_an_at_sign_is_still_found() {
        // Splitting on the first `@` rather than the last would take only part
        // of the password and leave the rest in the log.
        let mut values = Vec::new();
        collect_url_auth("mongodb://user:p@ss@db.example/app", &mut values);
        assert!(values.contains(&"p@ss".to_string()), "{values:?}");
    }

    #[test]
    fn a_url_without_credentials_collects_nothing() {
        let mut values = Vec::new();
        collect_url_auth("http://db.example:8123/", &mut values);
        collect_url_auth("not a url", &mut values);
        assert!(values.is_empty());
    }

    #[test]
    fn percent_encoding_covers_what_would_change_meaning() {
        assert_eq!(percent_encode("p@ss:word/1"), "p%40ss%3Aword%2F1");
        assert_eq!(percent_encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(percent_encode("plain-Token_1.0~"), "plain-Token_1.0~");
    }
}
