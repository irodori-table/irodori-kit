<!-- i18n: language-switcher -->
[English](building-connector-extension.md) | [日本語](building-connector-extension.ja.md)

# コネクター拡張機能の構築

これは、SDKがテンプレートファーストでnpmパッケージがまだ非公開の間に、Irodoriネイティブコネクター拡張機能を構築するための公開されサポートされたフローです。

## 前提条件

- Rust stable。
- Irodoriリポジトリで使用されるSDKツール用のNode.js 24。
- `irodori-kit`のチェックアウト。
- 公式コネクター作業の場合、`registry/catalog/connector-repositories.json`とスキャフォールドツールを含む兄弟の`irodori-table`のチェックアウト。

推奨レイアウト:

```text
workspace/
  irodori-kit/
  irodori-table/
  irodori-extensions/
    irodori-extension-example/
```

## 1. スキャフォールド

公式コネクターリポジトリはアプリレジストリから生成されます:

```sh
cd irodori-table
IRODORI_EXTENSIONS_ROOT=../irodori-extensions \
  node tools/extensions/scaffold-connector-repos.mjs
```

既に手書きのドライバー作業が含まれているリポジトリに対して、ドライバーを保持するようにスキャフォールドが対応されていない限り、スキャフォールドを再実行しないでください。

サードパーティの作者は既存の公開コネクターリポジトリの形をコピーし、次を更新できます:

- `irodori.extension.json`
- `connector.config.json`
- `Cargo.toml`
- `src/lib.rs`
- `src/driver.rs`

## 2. 共有ネイティブABIの使用

ネイティブコネクタークレートはgitタグで`irodori-connector-abi`に依存すべきです:

```toml
[dependencies]
irodori-connector-abi = { git = "https://github.com/irodori-table/irodori-kit", tag = "v0.9.0" }
serde_json = "1"
```

`driver.rs`はコネクターの動作に集中させてください。ABIクレートを`abi`として再エクスポートし、既存のドライバーコードがローカルのunsafeバッファコードなしで`crate::abi::...`を使えるようにします:

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

このマクロはデスクトップホストが期待する6つのネイティブエントリポイントをエクスポートします:

- `irodori_extension_abi_version`
- `irodori_connector_engine_json`
- `irodori_extension_manifest_json`
- `irodori_connector_config_json`
- `irodori_connector_call_json`
- `irodori_connector_free_buffer`

## 3. マニフェストの検証

`irodori-kit/packages/extension-sdk`からSDKバリデーターを実行します。`IRODORI_EXTENSION_MANIFEST_ROOTS`を1つ以上のコネクターのチェックアウトに向けてください:

```sh
cd irodori-kit/packages/extension-sdk
npm ci
IRODORI_EXTENSION_MANIFEST_ROOTS=../../../irodori-extensions/irodori-extension-example \
  npm run validate
```

複数のルートはプラットフォームのパス区切り文字（macOS/Linuxでは`:`、Windowsでは`;`）で区切れます。

## 4. ローカル開発ツールの実行

TypeScriptやマニフェストのみの拡張作業の場合、SDK開発ヘルパーはテンプレートまたは拡張ディレクトリを一度だけ実行できます:

```sh
node bin/irodori-extension-dev.mjs templates/typescript-basic --once
```

ネイティブコネクターリポジトリはローカルのRustチェックも実行すべきです:

```sh
cargo fmt --all -- --check
cargo test
```

## ローカルABIの共同開発

`irodori-kit`タグが存在しない状態でコネクター群を移行する場合、群のルートに1つのパッチを置き、すべてのコネクターのチェックアウトが兄弟のkitチェックアウトから共有ABIクレートを解決するようにします:

```toml
# irodori-extensions/.cargo/config.toml
[patch."https://github.com/irodori-table/irodori-kit"]
irodori-connector-abi = { path = "../irodori-kit/irodori-connector-abi" }
```

リリース検証前にこのパッチは削除してください。リリース済みのコネクターリポジトリは`irodori-connector-abi`を同じ`irodori-kit`のgitタグに固定すべきです。

## 5. パッケージングとカタログ

公式マーケットプレイスコネクターはカタログメタデータをリポジトリと整合させる必要があります:

- `irodori.extension.json`
- `connector.config.json`
- `registry/catalog/index.json`
- `registry/catalog/catalog.json`
- `registry/catalog/connector-repositories.json`

リリースアーカイブはマニフェストとコネクター設定、ネイティブモジュールをマニフェストとコネクター設定で宣言されたパスの下に含める必要があります。

公式リポジトリはCI呼び出し元と同じ固定された`irodori-kit`タグの再利用可能な`extension-release.yml`ワークフローを使用します。`v<manifest.version>`タグは6つのサポートされるGitHubホストランナーターゲットでネイティブアーカイブをビルドします:

- `x86_64-linux` と `aarch64-linux`
- `x86_64-macos` と `aarch64-macos`
- `x86_64-windows` と `aarch64-windows`

呼び出し元は手動の`release_tag`入力も受け付け、既存の不変タグを再ビルドしてプラットフォームアーカイブの欠落を補填できます（拡張バージョンは変更しません）。

各アーカイブ名は`-<target>.tar.gz`で終わり、リリースワークフローはアーカイブを不変タグに公開します。各拡張リポジトリに`IRODORI_CATALOG_TOKEN`リポジトリシークレットを設定し、`irodori-table/irodori-table`でワークフローをディスパッチする権限を持たせてください（リポジトリが組織に移動した場合は組織レベルのシークレットで代替可能）。リリースはカタログ同期をトリガーし、タグ、バージョン、プラットフォームアセット名、GitHub提供のSHA-256ダイジェストを記録します。ディスパッチが一時的に利用できない場合のフォールバックとして5分ごとのスケジュールされたカタログ同期があります。

## 現在の例

SDKがnpmに公開されるまで、公開コネクターリポジトリを例として使用してください:

- <https://github.com/irodori-table/irodori-extension-duckdb>
- <https://github.com/irodori-table/irodori-extension-memgraph>
- <https://github.com/irodori-table/irodori-extension-redis>
