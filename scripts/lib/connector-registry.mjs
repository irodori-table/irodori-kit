/**
 * Where the connector fleet is enumerated.
 *
 * There is more than one catalog. The lakehouse line was split out of
 * irodori-table into its own repository, and this audit kept reading only the
 * irodori-table catalog — so it went on reporting a consistent fleet while
 * covering 29 of the 35 connectors, with the six lakehouse repositories
 * checked by nothing. A registry list makes that failure impossible to repeat
 * silently: a line that cannot be read is an error, not a smaller fleet.
 */
import { KIT_OWNER } from "./kit.mjs";

export const EXPECTED_OWNER = KIT_OWNER;

const CATALOG_PATH = "registry/catalog/connector-repositories.json";

function catalogUrl(repository) {
  return `https://raw.githubusercontent.com/${KIT_OWNER}/${repository}/main/${CATALOG_PATH}`;
}

/** Every catalog that enumerates connector repositories, by product line. */
export const REGISTRIES = Object.freeze([
  Object.freeze({ line: "core", url: catalogUrl("irodori-table") }),
  Object.freeze({ line: "lakehouse", url: catalogUrl("irodori-lakehouse") }),
]);

export function parseConnectorInventory(text) {
  const inventory = JSON.parse(text);
  if (!inventory || typeof inventory !== "object" || Array.isArray(inventory)) {
    throw new Error("connector inventory must be a JSON object");
  }
  if (inventory.owner !== EXPECTED_OWNER) {
    throw new Error(
      `connector inventory owner must be ${EXPECTED_OWNER}, found ${String(inventory.owner)}`,
    );
  }
  if (
    !Array.isArray(inventory.repositories) ||
    inventory.repositories.length === 0
  ) {
    throw new Error("connector inventory must contain at least one repository");
  }

  const names = inventory.repositories.map((entry) => entry?.name);
  const invalid = names.filter(
    (name) =>
      typeof name !== "string" || !/^irodori-extension-[a-z0-9-]+$/.test(name),
  );
  if (invalid.length > 0) {
    throw new Error(
      `connector inventory contains invalid repository names: ${invalid.join(", ")}`,
    );
  }
  const duplicates = names.filter((name, index) => names.indexOf(name) !== index);
  if (duplicates.length > 0) {
    throw new Error(
      `connector inventory contains duplicate repositories: ${[...new Set(duplicates)].join(", ")}`,
    );
  }

  return {
    owner: inventory.owner,
    repositories: names.map((name) => ({ name })),
  };
}

/**
 * Fold the per-line inventories into one fleet.
 *
 * A repository listed by two lines is an error: it would be audited twice and,
 * worse, nobody would own moving it to a new kit tag.
 */
export function mergeInventories(parts) {
  if (parts.length === 0) {
    throw new Error("no connector registries were read");
  }
  const owners = [...new Set(parts.map(({ inventory }) => inventory.owner))];
  if (owners.length !== 1) {
    throw new Error(`connector registries disagree on owner: ${owners.join(", ")}`);
  }

  const seen = new Map();
  const repositories = [];
  for (const { line, inventory } of parts) {
    for (const { name } of inventory.repositories) {
      const already = seen.get(name);
      if (already) {
        throw new Error(
          `${name} is listed by both the ${already} and ${line} registries`,
        );
      }
      seen.set(name, line);
      repositories.push({ name, line });
    }
  }

  return {
    owner: owners[0],
    lines: parts.map(({ line }) => line),
    repositories,
  };
}

/** Count of repositories per line, for the summary a passing audit prints. */
export function inventoryBreakdown(inventory) {
  return inventory.lines
    .map(
      (line) =>
        `${line} ${inventory.repositories.filter((r) => r.line === line).length}`,
    )
    .join(", ");
}

export function rawRepositoryFileUrl(owner, repository, path, ref = "main") {
  const encodedPath = path.split("/").map(encodeURIComponent).join("/");
  return (
    `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/` +
    `${encodeURIComponent(repository)}/${encodeURIComponent(ref)}/${encodedPath}`
  );
}
