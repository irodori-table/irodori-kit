#!/usr/bin/env node
/**
 * Check that every connector repository follows one irodori-kit baseline.
 *
 * The live command reads the connector registries and repository files from
 * raw.githubusercontent.com. Parsing and comparison are kept in pure exported
 * functions so the policy can be tested without network access.
 */
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import {
  EXPECTED_OWNER,
  REGISTRIES,
  inventoryBreakdown,
  mergeInventories,
  parseConnectorInventory,
  rawRepositoryFileUrl,
} from "./lib/connector-registry.mjs";
import { KIT_GIT_URL, readWorkspaceTag } from "./lib/kit.mjs";
import { reporter } from "./lib/report.mjs";

const report = reporter("fleet-dependencies");

const CONNECTOR_PATHS = Object.freeze({
  cargoToml: "Cargo.toml",
  cargoLock: "Cargo.lock",
  ciWorkflow: ".github/workflows/ci.yml",
  releaseWorkflow: ".github/workflows/release.yml",
});

const OLD_OWNER = /github\.com\/hjosugi\//gi;

function oldOwnerReferences(text) {
  return [...text.matchAll(OLD_OWNER)].length;
}

function cargoDependency(text) {
  const body = text.match(/^\s*irodori-connector-abi\s*=\s*\{([\s\S]*?)\}/m)?.[1];
  if (!body) {
    return null;
  }
  return {
    git: body.match(/\bgit\s*=\s*"([^"]+)"/)?.[1] ?? null,
    tag: body.match(/\btag\s*=\s*"([^"]+)"/)?.[1] ?? null,
  };
}

function lockedDependencies(text) {
  return text
    .split(/^\s*\[\[package\]\]\s*$/m)
    .filter((candidate) =>
      /^\s*name\s*=\s*"irodori-connector-abi"\s*$/m.test(candidate),
    )
    .map((stanza) => {
      const source =
        stanza.match(/^\s*source\s*=\s*"([^"]+)"\s*$/m)?.[1] ?? null;
      return {
        source,
        tag: source?.match(/[?&]tag=([^#&]+)/)?.[1] ?? null,
      };
    });
}

function workflowReferences(text, workflow) {
  const escaped = workflow.replaceAll(".", "\\.");
  return [
    ...text.matchAll(
      new RegExp(
        `^\\s*uses:\\s*([^/\\s]+)\\/irodori-kit\\/\\.github\\/workflows\\/${escaped}@([^\\s'\"#]+)`,
        "gm",
      ),
    ),
  ].map((match) => ({ owner: match[1], tag: match[2] }));
}

export function inspectConnector(repository, files) {
  const errors = [];
  const required = Object.keys(CONNECTOR_PATHS);
  for (const key of required) {
    if (typeof files?.[key] !== "string") {
      errors.push(`${repository}: missing ${CONNECTOR_PATHS[key]}`);
    }
  }
  if (errors.length > 0) {
    return { repository, tag: null, errors };
  }

  for (const key of ["cargoToml", "cargoLock"]) {
    const count = oldOwnerReferences(files[key]);
    if (count > 0) {
      errors.push(
        `${repository}: ${CONNECTOR_PATHS[key]} contains ${count} github.com/hjosugi reference(s)`,
      );
    }
  }

  const cargo = cargoDependency(files.cargoToml);
  if (!cargo) {
    errors.push(
      `${repository}: Cargo.toml has no inline irodori-connector-abi dependency`,
    );
  } else {
    if (cargo.git !== KIT_GIT_URL) {
      errors.push(
        `${repository}: Cargo.toml irodori-connector-abi git URL is ${String(cargo.git)}`,
      );
    }
    if (!cargo.tag) {
      errors.push(`${repository}: Cargo.toml irodori-connector-abi has no tag`);
    }
  }

  const locked = lockedDependencies(files.cargoLock);
  if (locked.length === 0) {
    errors.push(`${repository}: Cargo.lock has no irodori-connector-abi package`);
  } else {
    if (locked.length !== 1) {
      errors.push(
        `${repository}: Cargo.lock contains ${locked.length} irodori-connector-abi packages: ` +
          locked.map(({ tag }) => String(tag)).join(", "),
      );
    }
    for (const dependency of locked) {
      if (!dependency.source?.startsWith(`git+${KIT_GIT_URL}?tag=`)) {
        errors.push(
          `${repository}: Cargo.lock irodori-connector-abi source is ${String(dependency.source)}`,
        );
      }
      if (cargo?.tag && dependency.tag !== cargo.tag) {
        errors.push(
          `${repository}: Cargo.lock tag ${String(dependency.tag)} does not match Cargo.toml ${cargo.tag}`,
        );
      }
    }
  }

  const references = [
    ["CI", workflowReferences(files.ciWorkflow, "extension-ci.yml")],
    ["release", workflowReferences(files.releaseWorkflow, "extension-release.yml")],
  ];
  for (const [kind, found] of references) {
    if (found.length === 0) {
      errors.push(
        `${repository}: ${kind} workflow has no irodori-kit reusable workflow reference`,
      );
      continue;
    }
    if (found.length !== 1) {
      errors.push(
        `${repository}: ${kind} workflow contains ${found.length} irodori-kit reusable workflow references`,
      );
    }
    for (const reference of found) {
      if (reference.owner !== EXPECTED_OWNER) {
        errors.push(`${repository}: ${kind} workflow uses owner ${reference.owner}`);
      }
      if (cargo?.tag && reference.tag !== cargo.tag) {
        errors.push(
          `${repository}: ${kind} workflow tag ${reference.tag} does not match Cargo.toml ${cargo.tag}`,
        );
      }
    }
  }

  return { repository, tag: cargo?.tag ?? null, errors };
}

export function inspectFleet(inventory, filesByRepository, expectedTag = null) {
  const results = inventory.repositories.map(({ name }) =>
    inspectConnector(name, filesByRepository[name]),
  );
  const expected = new Set(inventory.repositories.map(({ name }) => name));
  const unexpected = Object.keys(filesByRepository).filter(
    (name) => !expected.has(name),
  );
  const errors = results.flatMap((result) => result.errors);
  if (unexpected.length > 0) {
    errors.push(`unexpected connector data: ${unexpected.sort().join(", ")}`);
  }

  const tags = [
    ...new Set(results.map((result) => result.tag).filter(Boolean)),
  ].sort();
  if (tags.length !== 1) {
    errors.push(
      `fleet uses ${tags.length} irodori-kit tags: ${tags.length > 0 ? tags.join(", ") : "none"}`,
    );
  } else if (expectedTag && tags[0] !== expectedTag) {
    errors.push(
      `fleet uses ${tags[0]}, but the current irodori-kit release baseline is ${expectedTag}`,
    );
  }
  return { tag: tags.length === 1 ? tags[0] : null, results, errors };
}

async function fetchText(url) {
  const response = await fetch(url, {
    headers: { "user-agent": "irodori-kit-fleet-consistency" },
  });
  if (!response.ok) {
    throw new Error(`${url}: HTTP ${response.status}`);
  }
  return response.text();
}

async function mapWithConcurrency(items, limit, task) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const index = next++;
      results[index] = await task(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

/** Read every registry, and fail the audit rather than silently cover fewer repositories. */
export async function readInventory(readText, registries = REGISTRIES) {
  const parts = await Promise.all(
    registries.map(async ({ line, url }) => {
      try {
        return { line, inventory: parseConnectorInventory(await readText(url)) };
      } catch (error) {
        throw new Error(
          `${line} registry (${url}): ${error instanceof Error ? error.message : error}`,
        );
      }
    }),
  );
  return mergeInventories(parts);
}

export async function auditFleet({
  readText = fetchText,
  registries = REGISTRIES,
  expectedTag = readWorkspaceTag(),
} = {}) {
  const inventory = await readInventory(readText, registries);
  const entries = await mapWithConcurrency(
    inventory.repositories,
    6,
    async ({ name }) => {
      const pairs = await Promise.all(
        Object.entries(CONNECTOR_PATHS).map(async ([key, path]) => [
          key,
          await readText(rawRepositoryFileUrl(inventory.owner, name, path)),
        ]),
      );
      return [name, Object.fromEntries(pairs)];
    },
  );
  return {
    inventory,
    report: inspectFleet(inventory, Object.fromEntries(entries), expectedTag),
  };
}

async function main() {
  const { inventory, report: audit } = await auditFleet();
  if (audit.errors.length > 0) {
    console.error(`${report.prefix}: inconsistent connector fleet\n`);
    audit.errors.forEach((error) => console.error(`  - ${error}`));
    process.exitCode = 1;
    return;
  }
  report.ok(
    `ok (${inventory.repositories.length} repositories — ` +
      `${inventoryBreakdown(inventory)} — on ${audit.tag})`,
  );
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(
      `${report.prefix}: ${error instanceof Error ? error.message : error}`,
    );
    process.exitCode = 1;
  });
}
