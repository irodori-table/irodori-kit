#![deny(unsafe_op_in_unsafe_fn)]

//! Shared native connector ABI helpers.
//!
//! Connector crates should re-export this crate as `abi` so existing drivers can
//! keep using `crate::abi::...`, then call [`irodori_export_connector!`] from
//! `src/lib.rs` to export the six native entrypoints expected by Irodori Table.

use serde_json::{json, Value};

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrodoriConnectorBuffer {
    pub ptr: *const u8,
    pub len: usize,
}

mod request;

pub use request::{
    collect_url_auth, option_bool, option_string, percent_encode, push_sensitive, redact,
    request_containers,
};

pub fn owned_buffer(value: String) -> IrodoriConnectorBuffer {
    let mut bytes = value.into_bytes().into_boxed_slice();
    let buffer = IrodoriConnectorBuffer {
        ptr: bytes.as_mut_ptr(),
        len: bytes.len(),
    };
    std::mem::forget(bytes);
    buffer
}

pub fn json_buffer(value: Value) -> IrodoriConnectorBuffer {
    owned_buffer(value.to_string())
}

pub fn free_owned_buffer(buffer: IrodoriConnectorBuffer) {
    if buffer.ptr.is_null() {
        return;
    }
    unsafe {
        let slice = std::ptr::slice_from_raw_parts_mut(buffer.ptr as *mut u8, buffer.len);
        drop(Box::from_raw(slice));
    }
}

#[allow(clippy::result_unit_err)]
pub fn buffer_to_string(buffer: IrodoriConnectorBuffer) -> Result<String, ()> {
    if buffer.ptr.is_null() {
        return if buffer.len == 0 {
            Ok(String::new())
        } else {
            Err(())
        };
    }
    let bytes = unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len) };
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| ())
}

pub fn ok(mut payload: serde_json::Map<String, Value>) -> IrodoriConnectorBuffer {
    payload.insert("ok".to_string(), Value::Bool(true));
    json_buffer(Value::Object(payload))
}

pub fn error(code: &str, message: impl Into<String>) -> IrodoriConnectorBuffer {
    json_buffer(json!({
        "ok": false,
        "error": {
            "code": code,
            "message": message.into()
        }
    }))
}

pub fn parse_request(
    buffer: IrodoriConnectorBuffer,
) -> Result<Option<Value>, IrodoriConnectorBuffer> {
    let request = buffer_to_string(buffer).map_err(|_| {
        error(
            "connector.invalidRequest",
            "Connector request buffer must be empty or valid UTF-8 JSON.",
        )
    })?;
    let trimmed = request.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    serde_json::from_str::<Value>(trimmed)
        .map(Some)
        .map_err(|err| {
            error(
                "connector.invalidJson",
                format!("Connector request must be valid JSON: {err}"),
            )
        })
}

pub fn request_method(request: Option<&Value>) -> Result<&str, IrodoriConnectorBuffer> {
    match request {
        None => Ok("health"),
        Some(value) => value
            .get("method")
            .and_then(Value::as_str)
            .filter(|method| !method.trim().is_empty())
            .ok_or_else(|| {
                error(
                    "connector.invalidRequest",
                    "Connector request needs a string method.",
                )
            }),
    }
}

pub fn string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
}

pub fn profile_field<'a>(request: &'a Value, field: &str) -> Option<&'a str> {
    string_field(request, field).or_else(|| {
        request
            .get("profile")
            .and_then(|profile| string_field(profile, field))
    })
}

pub fn connection_id(request: Option<&Value>) -> String {
    request
        .and_then(|value| {
            string_field(value, "connectionId")
                .or_else(|| string_field(value, "id"))
                .or_else(|| {
                    value
                        .get("profile")
                        .and_then(|profile| string_field(profile, "id"))
                })
        })
        .unwrap_or("default")
        .trim()
        .to_string()
}

pub fn max_rows(request: &Value) -> usize {
    request
        .get("maxRows")
        .or_else(|| request.get("limit"))
        .and_then(Value::as_u64)
        .unwrap_or(10_000)
        .clamp(1, 100_000) as usize
}

#[macro_export]
macro_rules! irodori_export_connector {
    (
        engine: $engine:expr,
        driver: $driver:ident,
        config: $config:literal,
        manifest: $manifest:literal,
        driver_linked: $driver_linked:expr $(,)?
    ) => {
        #[allow(unused_imports)]
        pub use $crate::IrodoriConnectorBuffer;

        pub const ABI_VERSION: u32 = 1;
        pub const ENGINE: &str = $engine;
        #[allow(dead_code)]
        pub const DRIVER_LINKED: bool = $driver_linked;
        pub const CONFIG_JSON: &str = include_str!($config);
        pub const MANIFEST_JSON: &str = include_str!($manifest);

        #[no_mangle]
        pub extern "C" fn irodori_extension_abi_version() -> u32 {
            ABI_VERSION
        }

        #[no_mangle]
        pub extern "C" fn irodori_connector_engine_json() -> $crate::IrodoriConnectorBuffer {
            $crate::owned_buffer(ENGINE.to_string())
        }

        #[no_mangle]
        pub extern "C" fn irodori_extension_manifest_json() -> $crate::IrodoriConnectorBuffer {
            $crate::owned_buffer(MANIFEST_JSON.to_string())
        }

        #[no_mangle]
        pub extern "C" fn irodori_connector_config_json() -> $crate::IrodoriConnectorBuffer {
            $crate::owned_buffer(CONFIG_JSON.to_string())
        }

        #[no_mangle]
        pub extern "C" fn irodori_connector_call_json(
            request: $crate::IrodoriConnectorBuffer,
        ) -> $crate::IrodoriConnectorBuffer {
            $driver::call_json(request)
        }

        #[no_mangle]
        pub extern "C" fn irodori_connector_free_buffer(buffer: $crate::IrodoriConnectorBuffer) {
            $crate::free_owned_buffer(buffer);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn borrowed_buffer(value: &'static str) -> IrodoriConnectorBuffer {
        IrodoriConnectorBuffer {
            ptr: value.as_ptr(),
            len: value.len(),
        }
    }

    fn borrowed_bytes(value: &'static [u8]) -> IrodoriConnectorBuffer {
        IrodoriConnectorBuffer {
            ptr: value.as_ptr(),
            len: value.len(),
        }
    }

    fn owned_to_string(buffer: IrodoriConnectorBuffer) -> String {
        let value = buffer_to_string(buffer).unwrap();
        free_owned_buffer(buffer);
        value
    }

    #[test]
    fn buffer_round_trips_owned_utf8() {
        let buffer = owned_buffer("irodori database".to_string());
        assert_eq!(owned_to_string(buffer), "irodori database");
    }

    #[test]
    fn null_empty_buffer_is_empty_string() {
        assert_eq!(
            buffer_to_string(IrodoriConnectorBuffer {
                ptr: std::ptr::null(),
                len: 0,
            }),
            Ok(String::new()),
        );
    }

    #[test]
    fn rejects_invalid_utf8_and_invalid_json() {
        assert!(buffer_to_string(borrowed_bytes(&[0xff, 0xfe])).is_err());
        let error = parse_request(borrowed_buffer("{")).unwrap_err();
        assert!(owned_to_string(error).contains("connector.invalidJson"));
    }

    #[test]
    fn parses_request_helpers() {
        let request = parse_request(borrowed_buffer(
            r#"{"method":"query","connectionId":"main","maxRows":42}"#,
        ))
        .unwrap()
        .unwrap();

        assert_eq!(request_method(Some(&request)).unwrap(), "query");
        assert_eq!(connection_id(Some(&request)), "main");
        assert_eq!(max_rows(&request), 42);
    }

    mod exported {
        mod driver {
            pub fn call_json(
                _request: crate::IrodoriConnectorBuffer,
            ) -> crate::IrodoriConnectorBuffer {
                crate::ok(serde_json::Map::new())
            }
        }

        crate::irodori_export_connector!(
            engine: "test-engine",
            driver: driver,
            config: "../Cargo.toml",
            manifest: "../Cargo.toml",
            driver_linked: false,
        );
    }

    #[test]
    fn export_macro_generates_native_entrypoints() {
        assert_eq!(exported::irodori_extension_abi_version(), 1);
        assert_eq!(
            owned_to_string(exported::irodori_connector_engine_json()),
            "test-engine",
        );
        assert!(exported::CONFIG_JSON.contains("irodori-connector-abi"));
        assert!(
            owned_to_string(exported::irodori_connector_call_json(borrowed_buffer("")))
                .contains(r#""ok":true"#),
        );
    }
}
