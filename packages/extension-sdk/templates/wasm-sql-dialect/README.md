<!-- i18n: language-switcher -->
[English](README.md) | [日本語](README.ja.md)

# Wasm SQL Dialect Skeleton

This template is licensed as `0BSD`.

It reserves the Rust/Wasm path for high-performance dialect work such as parsers,
formatters, completion enrichers, and renderers. The host ABI is still marked
`irodori-sql-dialect-v0`, so keep logic isolated from the exported ABI shim while
the desktop extension host stabilizes.
