<!-- i18n: language-switcher -->
[English](README.md) | [日本語](README.ja.md)

# irodori-kit

Irodori Tableの共有基盤。

## 含まれるもの

- 接続、セキュリティ、補完、生成、IO、プロキシ、セキュアストレージ、拡張機能、ヘッドレスサーバーのためのRustクレート。
- `irodori-connector-abi`、インストール可能なコネクター拡張機能で使用される共有ネイティブコネクターABIヘルパーとエクスポートマクロ。
- `packages/extension-sdk`、拡張機能用のTypeScript SDKとテンプレート。
- `packaging/`、Irodori製品向けの共有リリースおよびパッケージマネージャーテンプレート。

`irodori-table`はこのリポジトリをGitタグで利用します。

## 開発

```sh
cargo fmt --all -- --check
cargo test --workspace
npm --prefix packages/extension-sdk run check
```

拡張SDKは現在、このリポジトリからテンプレートファーストで利用されています。
詳細は`packages/extension-sdk/README.md`および
`packages/extension-sdk/docs/building-connector-extension.md`を参照してください。

ライセンス: `0BSD`。

## ライセンス

0BSD。ほぼあらゆる目的でこのプロジェクトを使用、コピー、改変、配布できます。