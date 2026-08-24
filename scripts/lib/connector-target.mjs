/**
 * Opening a connector working tree, for the two ratchets that read one.
 *
 * Both the auth and the field check need the same four things before they can
 * say anything: the manifest exists, it parses, it names an extension, and the
 * Rust source is readable. Both used to spell that out themselves.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { connectorRustSource } from "./connector-source.mjs";

export const CONNECTOR_CONFIG = "connector.config.json";
export const CONNECTOR_DRIVER = "src/driver.rs";

/**
 * Open the connector rooted at `root`, reporting through `report`.
 *
 * Returns null when there is no connector manifest — the caller decides
 * whether that is a skip or a failure. Anything else that stops the check from
 * being meaningful exits through `report.fail`.
 */
export function openConnector(root, report) {
  const configPath = join(root, CONNECTOR_CONFIG);
  if (!existsSync(configPath)) {
    return null;
  }

  let config;
  try {
    config = JSON.parse(readFileSync(configPath, "utf8"));
  } catch (error) {
    report.fail(`${CONNECTOR_CONFIG} is not valid JSON: ${error.message}`);
  }

  const extensionId = config.extensionId;
  if (!extensionId) {
    report.fail(`${CONNECTOR_CONFIG} has no extensionId`);
  }

  return {
    root,
    config,
    extensionId,
    connection: config.connector?.connection ?? {},
    hasDriver: existsSync(join(root, CONNECTOR_DRIVER)),

    /** The comment-free Rust surface both ratchets look for evidence in. */
    source() {
      return connectorRustSource(join(root, "src"));
    },
  };
}
