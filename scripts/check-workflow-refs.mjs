#!/usr/bin/env node
/**
 * Fail when a reusable workflow's references to this repository drift from the
 * version being released, or from the current owner.
 *
 * These references have broken the fleet three separate ways:
 *
 * 1. `extension-release.yml` named `hjosugi/irodori-kit` after the transfer. git
 *    and the REST API follow a repository redirect; a reusable workflow `uses:`
 *    does not. Every release failed at startup with no jobs and no logs, and
 *    nothing else broke to point at the cause.
 * 2. `extension-release.yml` called `extension-ci.yml` at an older tag than the
 *    one being cut.
 * 3. `extension-ci.yml` checked out this repository at `ref: v0.7.5` while the
 *    workflow itself moved on, so a step added later referenced a script the
 *    checkout did not contain — and it broke all 35 extension repositories at
 *    once, only after they adopted the new tag.
 *
 * All three are the same mistake: a workflow that names its own version has to
 * be updated in step with it, and nothing checked.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const OWNER = "irodori-table";

const cargo = readFileSync(join(ROOT, "Cargo.toml"), "utf8");
const version = cargo.match(/^\[workspace\.package\][\s\S]*?^version = "([^"]+)"/m)?.[1];
if (!version) {
  console.error("check-workflow-refs: no [workspace.package] version in Cargo.toml");
  process.exit(1);
}
const expected = `v${version}`;

const dir = join(ROOT, ".github", "workflows");
const problems = [];

for (const name of readdirSync(dir).filter((f) => f.endsWith(".yml"))) {
  const text = readFileSync(join(dir, name), "utf8");
  text.split("\n").forEach((line, index) => {
    const where = `${name}:${index + 1}`;

    // Any reference to this repository must name the current owner.
    const owner = line.match(/([A-Za-z0-9_-]+)\/irodori-kit/);
    if (owner && owner[1] !== OWNER) {
      problems.push(
        `${where}: references ${owner[1]}/irodori-kit — a reusable workflow ` +
          `reference does not follow a repository transfer, so this cannot resolve`,
      );
    }

    // A reusable workflow calling into this repository, or checking it out,
    // must use the version being released.
    const usesTag = line.match(/irodori-kit\/\.github\/workflows\/[\w-]+\.yml@(v[\d.]+)/);
    if (usesTag && usesTag[1] !== expected) {
      problems.push(`${where}: calls ${usesTag[1]} but this tree is ${expected}`);
    }
    const refTag = line.match(/^\s*ref:\s*(v[\d.]+)\s*$/);
    if (refTag && refTag[1] !== expected) {
      problems.push(`${where}: checks out ${refTag[1]} but this tree is ${expected}`);
    }
  });
}

if (problems.length > 0) {
  console.error("check-workflow-refs: workflow self-references are out of step\n");
  problems.forEach((p) => console.error(`  ${p}`));
  console.error(
    `\nEvery self-reference must be ${expected} and owned by ${OWNER}. A tag that ` +
      `ships a workflow pointing at an older tag of itself breaks every consumer ` +
      `that adopts it, and does so only once they adopt it.`,
  );
  process.exit(1);
}

console.log(`check-workflow-refs: ok (${expected}, owner ${OWNER})`);
