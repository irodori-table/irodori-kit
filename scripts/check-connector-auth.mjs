#!/usr/bin/env node
/**
 * Ratchet connector.config.json authMethods against their Rust implementation.
 * Known debt lives in connector-auth-baseline.json and can only shrink.
 *
 * Usage: node check-connector-auth.mjs <manifest-root>
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { analyzeAuthMethods } from "./lib/connector-auth-evidence.mjs";
import { connectorRustSource } from "./lib/connector-source.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const BASELINE_PATH = join(HERE, "..", "connector-auth-baseline.json");

function fail(message) {
  console.error(`connector-auth: ${message}`);
  process.exit(1);
}

const root = resolve(process.argv[2] ?? ".");
const configPath = join(root, "connector.config.json");
const driverPath = join(root, "src", "driver.rs");

if (!existsSync(configPath)) {
  console.log("connector-auth: no connector.config.json — skipping");
  process.exit(0);
}

let config;
try {
  config = JSON.parse(readFileSync(configPath, "utf8"));
} catch (error) {
  fail(`connector.config.json is not valid JSON: ${error.message}`);
}

const extensionId = config.extensionId;
if (!extensionId) {
  fail("connector.config.json has no extensionId");
}

const declared = config.connector?.connection?.authMethods ?? [];
if (declared.length === 0) {
  console.log(`connector-auth: ${extensionId} declares no auth methods`);
  process.exit(0);
}
if (!existsSync(driverPath)) {
  fail(
    `${extensionId} declares ${declared.length} auth methods but has no src/driver.rs to implement them`,
  );
}

const source = connectorRustSource(join(root, "src"));
const analysis = analyzeAuthMethods(config, source);
if (analysis.unknown.length > 0) {
  fail(
    `unknown auth method id(s): ${analysis.unknown.join(", ")}. Add them to ` +
      `AUTH_EVIDENCE in scripts/lib/connector-auth-evidence.mjs with the Rust ` +
      `identifiers that prove they are implemented.`,
  );
}

const baseline = JSON.parse(readFileSync(BASELINE_PATH, "utf8"));
const allowed = baseline.connectors?.[extensionId] ?? [];
const added = analysis.unimplemented.filter((id) => !allowed.includes(id));
const resolved = allowed.filter((id) => !analysis.unimplemented.includes(id));

if (added.length > 0) {
  console.error(
    `connector-auth: ${extensionId} declares auth method(s) with no implementation in src/:\n` +
      added.map((id) => `  - ${id}`).join("\n") +
      `\n\nImplement them, or drop them from connector.config.json. A declaration\n` +
      `the driver does not honour tells the catalog and docs this connector\n` +
      `supports something it does not. See irodori-table/irodori-table#232.`,
  );
}
if (resolved.length > 0) {
  console.error(
    `connector-auth: ${extensionId} has baseline entries that are now implemented:\n` +
      resolved.map((id) => `  - ${id}`).join("\n") +
      `\n\nRemove them from connector-auth-baseline.json in irodori-kit so the\n` +
      `remaining debt stays accurate.`,
  );
}
if (added.length > 0 || resolved.length > 0) {
  process.exit(1);
}

const remaining = analysis.unimplemented.length;
console.log(
  remaining === 0
    ? `connector-auth: ${extensionId} — all ${analysis.declared.length} declared methods have an implementation`
    : `connector-auth: ${extensionId} — ${analysis.declared.length - remaining}/${analysis.declared.length} implemented, ` +
        `${remaining} known gap(s) in the baseline: ${analysis.unimplemented.join(", ")}`,
);
