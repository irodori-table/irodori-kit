<!-- i18n: language-switcher -->
[English](README.md) | [日本語](README.ja.md)

# irodori-kit

Shared foundation for Irodori Table.

## Contains

- Rust crates for connections, security, completion, generation, IO, proxying,
  secure storage, extensions, and the headless server.
- `irodori-connector-abi`, the shared native connector ABI helpers and export
  macro used by installable connector extensions.
- `packages/extension-sdk`, the TypeScript SDK and templates for extensions.
- `packaging/`, shared release and package-manager templates for Irodori
  products.

`irodori-table` consumes this repo by Git tag.

## Develop

```sh
cargo fmt --all -- --check
cargo test --workspace
npm --prefix packages/extension-sdk run check
```

The extension SDK is currently consumed template-first from this repository.
See `packages/extension-sdk/README.md` and
`packages/extension-sdk/docs/building-connector-extension.md`.

License: `0BSD`.

## License

0BSD. You can use, copy, modify, and distribute this project for almost any purpose.
