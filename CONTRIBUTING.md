# Contributing

Irodori Kit is the shared foundation workspace for Irodori Table. Keep changes
small, source-owned, and easy to verify from this repository.

## Clean-Room Rules

Follow the Irodori clean-room policy before using reference products, source
code, screenshots, snippets, themes, or generated assets:

<https://irodori-table.github.io/irodori-docs/clean-room.html>

Project-authored code, SDK templates, and examples use `MIT OR 0BSD` unless a
file states otherwise.

## Local Checks

```sh
cargo fmt --all -- --check
cargo test --workspace
npm --prefix packages/extension-sdk ci
npm --prefix packages/extension-sdk run check
```

Run the SDK manifest validator separately when changing templates, manifest
schema, or connector extension examples:

```sh
npm --prefix packages/extension-sdk run validate
```

Run type generation when changing `irodori-extension` Rust API structs:

```sh
npm --prefix packages/extension-sdk run typegen
```

## Repo Boundaries

- Rust foundation crates live at the workspace root.
- The TypeScript extension SDK, schema, templates, and local dev helper live in
  `packages/extension-sdk`.
- Packaging templates live under `packaging/`.
- App-specific UI/runtime behavior belongs in `irodori-table`.
- Connector implementation work belongs in one `irodori-extension-*` repository
  at a time.

Do not hand-edit generated SDK API output without changing the Rust source and
running the generator.
