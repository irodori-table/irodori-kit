import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import { runInNewContext } from "node:vm";
import { test } from "node:test";

const workflow = readFileSync(new URL("../.github/workflows/extension-release.yml", import.meta.url), "utf8");
const code = workflow.match(/node <<'DUCKDB_RUNTIME'\n([\s\S]*?)\n\s*DUCKDB_RUNTIME/)?.[1];
assert.ok(code, "release workflow must stage the actual Cargo-linked runtime");
const require = createRequire(import.meta.url);

function fixture(platform, callback) {
  const root = mkdtempSync(join(tmpdir(), "duckdb-runtime-"));
  try {
    const env = { RUNNER_TEMP: join(root, "tmp"), CARGO_TARGET_DIR: join(root, "target") };
    mkdirSync(env.RUNNER_TEMP);
    mkdirSync(join(env.CARGO_TARGET_DIR, "release"), { recursive: true });
    const filename = { linux: "libduckdb.so", darwin: "libduckdb.dylib", win32: "duckdb.dll" }[platform];
    const runtime = (directory, content) => {
      const path = join(root, directory);
      mkdirSync(path, { recursive: true });
      writeFileSync(join(path, filename), content);
      return path;
    };
    const execute = (directories, extra = []) => {
      const event = { reason: "build-script-executed", package_id: "registry+https://github.com/rust-lang/crates.io-index#libduckdb-sys@1.20000.0", linked_paths: directories.map(path => `native=${path}`) };
      writeFileSync(join(env.RUNNER_TEMP, "native-build.jsonl"), [event, ...extra].map(value => JSON.stringify(value)).join("\n") + "\n");
      runInNewContext(code, { require, process: { env, platform }, console: { log() {} } });
      return readFileSync(join(env.CARGO_TARGET_DIR, "release", filename), "utf8");
    };
    callback({ runtime, execute });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

for (const platform of ["linux", "darwin", "win32"]) {
  test(`stage the currently linked runtime on ${platform}, ignoring stale caches`, () => fixture(platform, ({ runtime, execute }) => {
    runtime("target/duckdb-download/old", "stale-runtime");
    const selected = runtime("target/duckdb-download/v2.0.0", "current-runtime");
    assert.equal(execute([selected]), "current-runtime");
  }));
}

test("reject missing runtime bytes", () => fixture("linux", ({ execute }) => {
  assert.throws(() => execute([]), /runtime is missing/);
}));

test("reject incompatible libraries in the current link paths", () => fixture("linux", ({ runtime, execute }) => {
  assert.throws(() => execute([runtime("first", "one"), runtime("second", "two")]), /runtimes disagree/);
}));

test("allow identical copies in multiple Cargo link paths", () => fixture("linux", ({ runtime, execute }) => {
  assert.equal(execute([runtime("first", "same"), runtime("second", "same")]), "same");
}));

test("reject multiple libduckdb-sys package versions", () => fixture("linux", ({ runtime, execute }) => {
  const old = { reason: "build-script-executed", package_id: "registry+https://github.com/rust-lang/crates.io-index#libduckdb-sys@1.10503.0", linked_paths: [] };
  assert.throws(() => execute([runtime("current", "bytes")], [old]), /exactly one linked/);
}));
