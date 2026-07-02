# Building A Connector Extension

This is the public, supported flow for building an Irodori native connector
extension while the SDK is template-first and the npm package is still private.

## Prerequisites

- Rust stable.
- Node.js 24 for the SDK tooling used by Irodori repos.
- A checkout of `irodori-kit`.
- For official connector work, a sibling `irodori-table` checkout containing
  `registry/catalog/connector-repositories.json` and the scaffold tooling.

Suggested layout:

```text
workspace/
  irodori-kit/
  irodori-table/
  irodori-extensions/
    irodori-extension-example/
```

## 1. Scaffold

Official connector repos are generated from the app registry:

```sh
cd irodori-table
IRODORI_EXTENSIONS_ROOT=../irodori-extensions \
  node tools/extensions/scaffold-connector-repos.mjs
```

Do not rerun the scaffold over a repository that already contains hand-written
driver work unless the scaffold has been made driver-preserving for that repo.

Third-party authors can copy the shape from an existing public connector repo,
then update:

- `irodori.extension.json`
- `connector.config.json`
- `Cargo.toml`
- `src/lib.rs`
- `src/driver.rs`

## 2. Use The Shared Native ABI

Native connector crates should depend on `irodori-connector-abi` by git tag:

```toml
[dependencies]
irodori-connector-abi = { git = "https://github.com/hjosugi/irodori-kit", tag = "v0.6.0" }
serde_json = "1"
```

Keep `driver.rs` focused on connector behavior. Re-export the ABI crate as
`abi` so existing driver code can use `crate::abi::...` without local unsafe
buffer code:

```rust
mod driver;

pub use irodori_connector_abi as abi;

irodori_connector_abi::irodori_export_connector!(
    engine: "example",
    driver: driver,
    config: "../connector.config.json",
    manifest: "../irodori.extension.json",
    driver_linked: true,
);
```

The macro exports the six native entrypoints expected by the desktop host:

- `irodori_extension_abi_version`
- `irodori_connector_engine_json`
- `irodori_extension_manifest_json`
- `irodori_connector_config_json`
- `irodori_connector_call_json`
- `irodori_connector_free_buffer`

## 3. Validate The Manifest

Run the SDK validator from `irodori-kit/packages/extension-sdk`. Point
`IRODORI_EXTENSION_MANIFEST_ROOTS` at one or more connector checkouts:

```sh
cd irodori-kit/packages/extension-sdk
npm ci
IRODORI_EXTENSION_MANIFEST_ROOTS=../../../irodori-extensions/irodori-extension-example \
  npm run validate
```

Multiple roots can be separated with the platform path delimiter (`:` on
macOS/Linux, `;` on Windows).

## 4. Run Local Dev Tooling

For TypeScript and manifest-only extension work, the SDK dev helper can run a
template or extension directory once:

```sh
node bin/irodori-extension-dev.mjs templates/typescript-basic --once
```

Native connector repos should also run their local Rust checks:

```sh
cargo fmt --all -- --check
cargo test
```

## Local ABI Co-Development

When migrating the connector fleet before an `irodori-kit` tag exists, put one
patch in the fleet root so every connector checkout resolves the shared ABI crate
from the sibling kit checkout:

```toml
# irodori-extensions/.cargo/config.toml
[patch."https://github.com/hjosugi/irodori-kit"]
irodori-connector-abi = { path = "../irodori-kit/irodori-connector-abi" }
```

Remove this patch before release verification. Released connector repos should
pin `irodori-connector-abi` to the same `irodori-kit` git tag.

## 5. Package And Catalog

Official marketplace connectors must keep the catalog metadata aligned with the
repository:

- `irodori.extension.json`
- `connector.config.json`
- `registry/catalog/index.json`
- `registry/catalog/catalog.json`
- `registry/catalog/connector-repositories.json`

Release archives must contain the manifest, connector config, and native module
under the paths declared by the manifest and connector config.

## Current Examples

Use the public connector repos as examples until the SDK is published to npm:

- <https://github.com/hjosugi/irodori-extension-duckdb>
- <https://github.com/hjosugi/irodori-extension-memgraph>
- <https://github.com/hjosugi/irodori-extension-redis>
