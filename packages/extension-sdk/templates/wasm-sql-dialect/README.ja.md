<!-- i18n: language-switcher -->
[English](README.md) | [日本語](README.ja.md)

# Wasm SQL 方言スケルトン

このテンプレートは `0BSD` ライセンスです。

これは、パーサー、フォーマッター、補完強化、レンダラーなどの高性能な方言作業のために Rust/Wasm パスを予約します。ホスト ABI は依然として `irodori-sql-dialect-v0` とマークされているため、デスクトップ拡張ホストが安定するまでは、エクスポートされた ABI シムからロジックを分離しておいてください。