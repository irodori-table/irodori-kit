#!/usr/bin/env node
/**
 * Ratchet connector connection-field bindings against exact request-key reads
 * in the Rust driver. Known debt lives in connector-field-baseline.json.
 *
 * Usage: node check-connector-fields.mjs <manifest-root> [--report]
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  analyzeConnectorFields,
  fieldBaselineDiff,
} from "./lib/connector-fields.mjs";
import { connectorRustSource } from "./lib/connector-source.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const BASELINE_PATH = join(HERE, "..", "connector-field-baseline.json");

function fail(message) {
  console.error(`connector-fields: ${message}`);
  process.exit(1);
}

const args = process.argv.slice(2);
const report = args.includes("--report");
const root = resolve(args.find((arg) => !arg.startsWith("--")) ?? ".");
const configPath = join(root, "connector.config.json");
const driverPath = join(root, "src", "driver.rs");

if (!existsSync(configPath)) {
  console.log("connector-fields: no connector.config.json — skipping");
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
if (!existsSync(driverPath)) {
  fail(`${extensionId} has no src/driver.rs to consume declared connection fields`);
}

const source = connectorRustSource(join(root, "src"));
const analysis = analyzeConnectorFields(config, source);
if (analysis.auth.unknown.length > 0) {
  fail(
    `unknown auth method id(s): ${analysis.auth.unknown.join(", ")}. Teach the ` +
      `method-level guard about them before field coverage can be evaluated.`,
  );
}
if (report) {
  console.log(
    JSON.stringify(
      {
        extensionId,
        declared: analysis.declared,
        missing: analysis.missing,
      },
      null,
      2,
    ),
  );
  process.exit(0);
}

const baseline = JSON.parse(readFileSync(BASELINE_PATH, "utf8"));
const allowed = baseline.connectors?.[extensionId] ?? [];
const { added, resolved } = fieldBaselineDiff(analysis.missing, allowed);

if (added.length > 0) {
  console.error(
    `connector-fields: ${extensionId} declares request field(s) the Rust source never reads:\n` +
      added
        .map(
          ({ binding, origins }) =>
            `  - ${binding} (${origins.join(", ")})`,
        )
        .join("\n") +
      `\n\nRead each exact manifest binding, or remove the field declaration. The UI\n` +
      `submits these case-sensitive keys exactly as written. See\n` +
      `irodori-table/irodori-table#230 and #232.`,
  );
}
if (resolved.length > 0) {
  console.error(
    `connector-fields: ${extensionId} has stale field baseline entries:\n` +
      resolved.map((binding) => `  - ${binding}`).join("\n") +
      `\n\nRemove them from connector-field-baseline.json in irodori-kit so the\n` +
      `remaining debt stays accurate.`,
  );
}
if (added.length > 0 || resolved.length > 0) {
  process.exit(1);
}

const remaining = analysis.missing.length;
console.log(
  remaining === 0
    ? `connector-fields: ${extensionId} — all ${analysis.declared.length} declared bindings are read`
    : `connector-fields: ${extensionId} — ${analysis.declared.length - remaining}/${analysis.declared.length} read, ` +
        `${remaining} known gap(s) in the baseline: ${analysis.missing.map(({ binding }) => binding).join(", ")}`,
);
