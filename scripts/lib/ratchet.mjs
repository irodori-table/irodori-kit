/**
 * The baseline ratchet both connector checks run.
 *
 * A ratchet only lets known debt shrink. It fails in two directions: a new gap
 * that is not in the baseline, and a baseline entry that is no longer a gap.
 * The second direction is the one that keeps the file honest, and it is worded
 * and handled identically for auth methods and for field bindings — dynamodb
 * implementing `host` should read the same as a connector implementing
 * `webIdentity`.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { KIT_REPO, KIT_ROOT } from "./kit.mjs";
import { bullets } from "./report.mjs";

/** Read a baseline file from the repository root, e.g. connector-auth-baseline.json. */
export function readBaseline(file, root = KIT_ROOT) {
  return JSON.parse(readFileSync(join(root, file), "utf8"));
}

/** The recorded debt for one connector, or none. */
export function baselineEntries(baseline, extensionId) {
  return baseline.connectors?.[extensionId] ?? [];
}

/**
 * Report both directions of the ratchet and exit non-zero if either fired.
 *
 * `added` carries its own wording because a missing auth implementation and an
 * unread field binding call for different advice. `resolved` does not: the fix
 * is always to delete the entry from the baseline in this repository.
 */
export function reportRatchet(report, { extensionId, baselineFile, added, resolved }) {
  if (added.items.length > 0) {
    report.problem(`${extensionId} ${added.title}`, added.items, added.advice);
  }
  if (resolved.items.length > 0) {
    report.problem(
      `${extensionId} ${resolved.title}`,
      resolved.items,
      `Remove them from ${baselineFile} in ${KIT_REPO} so the\n` +
        `remaining debt stays accurate.`,
    );
  }
  if (added.items.length > 0 || resolved.items.length > 0) {
    process.exit(1);
  }
}

/**
 * The one-line summary a passing ratchet prints: everything covered, or how
 * much is covered and what the baseline still forgives.
 */
export function ratchetSummary({ extensionId, declared, gaps, whole, each }) {
  if (gaps.length === 0) {
    return `${extensionId} — all ${declared} declared ${whole}`;
  }
  return (
    `${extensionId} — ${declared - gaps.length}/${declared} ${each}, ` +
    `${gaps.length} known gap(s) in the baseline: ${gaps.join(", ")}`
  );
}
