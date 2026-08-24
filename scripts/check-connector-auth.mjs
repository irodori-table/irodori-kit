#!/usr/bin/env node
/**
 * Ratchet connector.config.json authMethods against their Rust implementation.
 * Known debt lives in connector-auth-baseline.json and can only shrink.
 *
 * Usage: node check-connector-auth.mjs <manifest-root>
 */
import { resolve } from "node:path";
import { analyzeAuthMethods } from "./lib/connector-auth-evidence.mjs";
import { CONNECTOR_DRIVER, openConnector } from "./lib/connector-target.mjs";
import {
  baselineEntries,
  ratchetSummary,
  readBaseline,
  reportRatchet,
} from "./lib/ratchet.mjs";
import { reporter } from "./lib/report.mjs";

const BASELINE_FILE = "connector-auth-baseline.json";
const report = reporter("connector-auth");

const connector = openConnector(resolve(process.argv[2] ?? "."), report);
if (!connector) {
  report.skip("no connector.config.json — skipping");
}

const declared = connector.connection.authMethods ?? [];
if (declared.length === 0) {
  report.skip(`${connector.extensionId} declares no auth methods`);
}
if (!connector.hasDriver) {
  report.fail(
    `${connector.extensionId} declares ${declared.length} auth methods but has no ${CONNECTOR_DRIVER} to implement them`,
  );
}

const analysis = analyzeAuthMethods(connector.config, connector.source());
if (analysis.unknown.length > 0) {
  report.fail(
    `unknown auth method id(s): ${analysis.unknown.join(", ")}. Add them to ` +
      `AUTH_EVIDENCE in scripts/lib/connector-auth-evidence.mjs with the Rust ` +
      `identifiers that prove they are implemented.`,
  );
}

const allowed = baselineEntries(readBaseline(BASELINE_FILE), connector.extensionId);
reportRatchet(report, {
  extensionId: connector.extensionId,
  baselineFile: BASELINE_FILE,
  added: {
    title: "declares auth method(s) with no implementation in src/",
    items: analysis.unimplemented.filter((id) => !allowed.includes(id)),
    advice:
      `Implement them, or drop them from connector.config.json. A declaration\n` +
      `the driver does not honour tells the catalog and docs this connector\n` +
      `supports something it does not. See irodori-table/irodori-table#232.`,
  },
  resolved: {
    title: "has baseline entries that are now implemented",
    items: allowed.filter((id) => !analysis.unimplemented.includes(id)),
  },
});

report.ok(
  ratchetSummary({
    extensionId: connector.extensionId,
    declared: analysis.declared.length,
    gaps: analysis.unimplemented,
    whole: "methods have an implementation",
    each: "implemented",
  }),
);
