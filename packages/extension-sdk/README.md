# Irodori Extension SDK

TypeScript SDK, manifest schema, and starter templates for Irodori Table
extensions.

## Consumption Mode

The SDK is currently **template-first**:

- clone or vendor this repository when building official or early third-party
  extensions;
- start from `templates/typescript-basic` for TypeScript extensions;
- start from `templates/wasm-sql-dialect` for Rust/Wasm dialect experiments;
- for native connector extensions, follow
  [`docs/building-connector-extension.md`](docs/building-connector-extension.md)
  and the public `irodori-extension-*` connector repositories.

The npm package name is reserved as `@irodori-table/extension-sdk`, but the
package remains private until the API is ready for a stable public publish. Until
then, local templates depend on the SDK with `file:../..`.

## Develop

```sh
npm install
npm run check
npm run build
```

Remove unused TypeScript imports:

```sh
npm run fix:imports
```

Run a template locally:

```sh
node bin/irodori-extension-dev.mjs templates/typescript-basic --once
```

Validate all bundled templates:

```sh
npm run validate
```

Generated API types come from the Rust `irodori-extension` crate:

```sh
npm run typegen
```

Check generated API drift without committing output:

```sh
npm run typegen:check
```

## Connector Extensions

Native connector extensions use this package for manifest validation and local
development, and use the Rust `irodori-connector-abi` crate for the native ABI
entrypoints. The current public connector examples are the
`hjosugi/irodori-extension-*` repositories, such as:

- <https://github.com/hjosugi/irodori-extension-duckdb>
- <https://github.com/hjosugi/irodori-extension-memgraph>

See [`docs/building-connector-extension.md`](docs/building-connector-extension.md)
for the scaffold-to-validate flow.

License: `MIT OR 0BSD`.
