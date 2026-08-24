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
import { join } from "node:path";
import { KIT_OWNER, KIT_REPO, KIT_ROOT, readWorkspaceTag } from "./lib/kit.mjs";
import { bullets, reporter } from "./lib/report.mjs";

const report = reporter("check-workflow-refs");

let expected;
try {
  expected = readWorkspaceTag();
} catch (error) {
  report.fail(error instanceof Error ? error.message : String(error));
}

const dir = join(KIT_ROOT, ".github", "workflows");
const problems = [];

for (const name of readdirSync(dir).filter((f) => f.endsWith(".yml"))) {
  const text = readFileSync(join(dir, name), "utf8");
  text.split("\n").forEach((line, index) => {
    const where = `${name}:${index + 1}`;

    // Any reference to this repository must name the current owner.
    const owner = line.match(new RegExp(`([A-Za-z0-9_-]+)\\/${KIT_REPO}`));
    if (owner && owner[1] !== KIT_OWNER) {
      problems.push(
        `${where}: references ${owner[1]}/${KIT_REPO} — a reusable workflow ` +
          `reference does not follow a repository transfer, so this cannot resolve`,
      );
    }

    // A reusable workflow calling into this repository, or checking it out,
    // must use the version being released.
    const usesTag = line.match(
      new RegExp(`${KIT_REPO}\\/\\.github\\/workflows\\/[\\w-]+\\.yml@(v[\\d.]+)`),
    );
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
  console.error(`${report.prefix}: workflow self-references are out of step\n`);
  console.error(bullets(problems));
  console.error(
    `\nEvery self-reference must be ${expected} and owned by ${KIT_OWNER}. A tag that ` +
      `ships a workflow pointing at an older tag of itself breaks every consumer ` +
      `that adopts it, and does so only once they adopt it.`,
  );
  process.exit(1);
}

report.ok(`ok (${expected}, owner ${KIT_OWNER})`);
