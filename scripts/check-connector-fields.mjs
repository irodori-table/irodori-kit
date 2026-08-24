#!/usr/bin/env node
/**
 * Ratchet connector connection-field bindings against exact request-key reads
 * in the Rust driver. Known debt lives in connector-field-baseline.json.
 *
 * Usage: node check-connector-fields.mjs <manifest-root> [--report]
 */
import { resolve } from "node:path";
import {
  analyzeConnectorFields,
  fieldBaselineDiff,
} from "./lib/connector-fields.mjs";
import { CONNECTOR_DRIVER, openConnector } from "./lib/connector-target.mjs";
import {
  baselineEntries,
  ratchetSummary,
  readBaseline,
  reportRatchet,
} from "./lib/ratchet.mjs";
import { reporter } from "./lib/report.mjs";

const BASELINE_FILE = "connector-field-baseline.json";
const report = reporter("connector-fields");

const args = process.argv.slice(2);
const asReport = args.includes("--report");
const root = resolve(args.find((arg) => !arg.startsWith("--")) ?? ".");

const connector = openConnector(root, report);
if (!connector) {
  report.skip("no connector.config.json — skipping");
}
if (!connector.hasDriver) {
  report.fail(
    `${connector.extensionId} has no ${CONNECTOR_DRIVER} to consume declared connection fields`,
  );
}

const analysis = analyzeConnectorFields(connector.config, connector.source());
if (analysis.auth.unknown.length > 0) {
  report.fail(
    `unknown auth method id(s): ${analysis.auth.unknown.join(", ")}. Teach the ` +
      `method-level guard about them before field coverage can be evaluated.`,
  );
}
if (asReport) {
  console.log(
    JSON.stringify(
      {
        extensionId: connector.extensionId,
        declared: analysis.declared,
        missing: analysis.missing,
      },
      null,
      2,
    ),
  );
  process.exit(0);
}

const allowed = baselineEntries(readBaseline(BASELINE_FILE), connector.extensionId);
const { added, resolved } = fieldBaselineDiff(analysis.missing, allowed);

reportRatchet(report, {
  extensionId: connector.extensionId,
  baselineFile: BASELINE_FILE,
  added: {
    title: "declares request field(s) the Rust source never reads",
    items: added.map(({ binding, origins }) => `${binding} (${origins.join(", ")})`),
    advice:
      `Read each exact manifest binding, or remove the field declaration. The UI\n` +
      `submits these case-sensitive keys exactly as written. See\n` +
      `irodori-table/irodori-table#230 and #232.`,
  },
  resolved: {
    title: "has stale field baseline entries",
    items: resolved,
  },
});

report.ok(
  ratchetSummary({
    extensionId: connector.extensionId,
    declared: analysis.declared.length,
    gaps: analysis.missing.map(({ binding }) => binding),
    whole: "bindings are read",
    each: "read",
  }),
);
