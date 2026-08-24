/**
 * What every check knows about this repository: who owns it, where it is, and
 * which tag the tree in hand will be released as.
 *
 * The owner used to be spelled out in each script. After the transfer to the
 * organization that meant four places to update, and a reusable workflow
 * reference does not follow a repository redirect, so a missed one fails only
 * once a connector adopts the tag.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const KIT_OWNER = "irodori-table";
export const KIT_REPO = "irodori-kit";
export const KIT_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** `https://github.com/irodori-table/irodori-kit`, the git dependency URL. */
export const KIT_GIT_URL = `https://github.com/${KIT_OWNER}/${KIT_REPO}`;

/** The `[workspace.package]` version of a workspace Cargo.toml. */
export function workspaceVersion(text) {
  const version = text.match(
    /^\[workspace\.package\][\s\S]*?^version\s*=\s*"([^"]+)"/m,
  )?.[1];
  if (!version) {
    throw new Error("workspace Cargo.toml has no [workspace.package] version");
  }
  return version;
}

/** That version as the release tag connectors pin: `v0.9.1`. */
export function workspaceTag(text) {
  return `v${workspaceVersion(text)}`;
}

/** The release tag of the checked-out tree. */
export function readWorkspaceTag(root = KIT_ROOT) {
  return workspaceTag(readFileSync(join(root, "Cargo.toml"), "utf8"));
}
