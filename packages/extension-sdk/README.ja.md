<!-- i18n: language-switcher -->
[English](README.md) | [日本語](README.ja.md)

# Irodori Extension SDK

Irodori Table拡張機能のためのTypeScript SDK、マニフェストスキーマ、およびスターターテンプレート。

## 利用方法

SDKは現在**テンプレートファースト**です：

- 公式または初期のサードパーティ拡張機能を構築する際は、このリポジトリをクローンまたはベンダーしてください；
- TypeScript拡張機能は`templates/typescript-basic`から開始してください；
- Rust/Wasm方言の実験は`templates/wasm-sql-dialect`から開始してください；
- ネイティブコネクタ拡張機能の場合は、[`docs/building-connector-extension.md`](docs/building-connector-extension.md)および公開されている`irodori-extension-*`コネクタリポジトリに従ってください。

npmパッケージ名は`@irodori-table/extension-sdk`として予約されていますが、APIが安定した公開準備が整うまではプライベートのままです。それまでは、ローカルテンプレートは`file:../..`でSDKに依存しています。

## 開発

```sh
npm install
npm run check
npm run build
```

未使用のTypeScriptインポートを削除：

```sh
npm run fix:imports
```

テンプレートをローカルで実行：

```sh
node bin/irodori-extension-dev.mjs templates/typescript-basic --once
```

すべてのバンドル済みテンプレートを検証：

```sh
npm run validate
```

生成されたAPI型はRustの`irodori-extension`クレートから取得：

```sh
npm run typegen
```

生成されたAPIの差分を出力をコミットせずにチェック：

```sh
npm run typegen:check
```

## コネクタ拡張機能

ネイティブコネクタ拡張機能は、マニフェスト検証とローカル開発にこのパッケージを使用し、ネイティブABIエントリポイントにはRustの`irodori-connector-abi`クレートを使用します。現在の公開コネクタ例は`hjosugi/irodori-extension-*`リポジトリ群で、例えば：

- <https://github.com/hjosugi/irodori-extension-duckdb>
- <https://github.com/hjosugi/irodori-extension-memgraph>

スキャフォールドから検証までの流れは[`docs/building-connector-extension.md`](docs/building-connector-extension.md)を参照してください。

ライセンス：`0BSD`。