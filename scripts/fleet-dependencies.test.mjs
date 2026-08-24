import assert from "node:assert/strict";
import test from "node:test";
import {
  auditFleet,
  inspectConnector,
  inspectFleet,
  readInventory,
} from "./check-fleet-dependencies.mjs";
import {
  inventoryBreakdown,
  mergeInventories,
  parseConnectorInventory,
  rawRepositoryFileUrl,
} from "./lib/connector-registry.mjs";
import { workspaceTag } from "./lib/kit.mjs";

function fixture(tag = "v0.8.4") {
  return {
    cargoToml: `
[dependencies]
irodori-connector-abi = {
  git = "https://github.com/irodori-table/irodori-kit",
  tag = "${tag}"
}
`,
    cargoLock: `
[[package]]
name = "irodori-connector-abi"
version = "0.8.4"
source = "git+https://github.com/irodori-table/irodori-kit?tag=${tag}#0123456789abcdef"
`,
    ciWorkflow: `
jobs:
  ci:
    uses: irodori-table/irodori-kit/.github/workflows/extension-ci.yml@${tag}
`,
    releaseWorkflow: `
jobs:
  release:
    uses: irodori-table/irodori-kit/.github/workflows/extension-release.yml@${tag}
`,
  };
}

test("inventory parsing validates owner, names, and duplicates", () => {
  const inventory = parseConnectorInventory(
    JSON.stringify({
      owner: "irodori-table",
      repositories: [
        { name: "irodori-extension-alpha", extensionId: "irodori.alpha" },
        { name: "irodori-extension-beta", extensionId: "irodori.beta" },
      ],
    }),
  );
  assert.deepEqual(inventory, {
    owner: "irodori-table",
    repositories: [
      { name: "irodori-extension-alpha" },
      { name: "irodori-extension-beta" },
    ],
  });
  assert.throws(
    () =>
      parseConnectorInventory(
        JSON.stringify({
          owner: "hjosugi",
          repositories: [{ name: "irodori-extension-alpha" }],
        }),
      ),
    /owner must be irodori-table/,
  );
  assert.throws(
    () =>
      parseConnectorInventory(
        JSON.stringify({
          owner: "irodori-table",
          repositories: [
            { name: "irodori-extension-alpha" },
            { name: "irodori-extension-alpha" },
          ],
        }),
      ),
    /duplicate repositories/,
  );
});

test("a connector passes only when Cargo, lock, CI, and release use one tag", () => {
  assert.deepEqual(inspectConnector("irodori-extension-alpha", fixture()), {
    repository: "irodori-extension-alpha",
    tag: "v0.8.4",
    errors: [],
  });

  const files = fixture();
  files.cargoLock = files.cargoLock.replace("irodori-table", "hjosugi");
  files.releaseWorkflow = files.releaseWorkflow.replace("v0.8.4", "v0.8.3");
  const report = inspectConnector("irodori-extension-alpha", files);
  assert.match(
    report.errors.join("\n"),
    /Cargo\.lock contains 1 github\.com\/hjosugi/,
  );
  assert.match(
    report.errors.join("\n"),
    /Cargo\.lock irodori-connector-abi source/,
  );
  assert.match(
    report.errors.join("\n"),
    /release workflow tag v0\.8\.3 does not match/,
  );
});

test("a connector rejects duplicate ABI lock packages", () => {
  const files = fixture();
  files.cargoLock += files.cargoLock.replaceAll("v0.8.4", "v0.8.3");
  const report = inspectConnector("irodori-extension-alpha", files);
  assert.match(
    report.errors.join("\n"),
    /Cargo\.lock contains 2 irodori-connector-abi packages: v0\.8\.4, v0\.8\.3/,
  );
  assert.match(
    report.errors.join("\n"),
    /Cargo\.lock tag v0\.8\.3 does not match Cargo\.toml v0\.8\.4/,
  );
});

test("a connector rejects duplicate reusable workflow references", () => {
  const files = fixture();
  files.ciWorkflow += files.ciWorkflow.replace("v0.8.4", "v0.8.3");
  const report = inspectConnector("irodori-extension-alpha", files);
  assert.match(
    report.errors.join("\n"),
    /CI workflow contains 2 irodori-kit reusable workflow references/,
  );
  assert.match(
    report.errors.join("\n"),
    /CI workflow tag v0\.8\.3 does not match Cargo\.toml v0\.8\.4/,
  );
});

test("fleet inspection rejects otherwise-valid repositories on different tags", () => {
  const inventory = {
    owner: "irodori-table",
    repositories: [
      { name: "irodori-extension-alpha" },
      { name: "irodori-extension-beta" },
    ],
  };
  const report = inspectFleet(inventory, {
    "irodori-extension-alpha": fixture("v0.8.3"),
    "irodori-extension-beta": fixture("v0.8.4"),
  });
  assert.equal(report.tag, null);
  assert.match(
    report.errors.at(-1),
    /fleet uses 2 irodori-kit tags: v0\.8\.3, v0\.8\.4/,
  );
});

test("fleet inspection requires the current workspace release baseline", () => {
  const inventory = {
    owner: "irodori-table",
    repositories: [
      { name: "irodori-extension-alpha" },
      { name: "irodori-extension-beta" },
    ],
  };
  const report = inspectFleet(
    inventory,
    {
      "irodori-extension-alpha": fixture("v0.8.3"),
      "irodori-extension-beta": fixture("v0.8.3"),
    },
    "v0.8.4",
  );
  assert.equal(report.tag, "v0.8.3");
  assert.match(
    report.errors.at(-1),
    /fleet uses v0\.8\.3, but the current irodori-kit release baseline is v0\.8\.4/,
  );
  assert.equal(workspaceTag("[workspace.package]\nversion = \"0.8.4\"\n"), "v0.8.4");
});

test("raw URLs encode repository refs and nested paths", () => {
  assert.equal(
    rawRepositoryFileUrl(
      "irodori-table",
      "irodori-extension-alpha",
      ".github/workflows/ci.yml",
      "release/test",
    ),
    "https://raw.githubusercontent.com/irodori-table/irodori-extension-alpha/release%2Ftest/.github/workflows/ci.yml",
  );
});

function inventoryFor(...names) {
  return JSON.stringify({
    owner: "irodori-table",
    repositories: names.map((name) => ({ name })),
  });
}

test("registries merge into one fleet, tagged by product line", () => {
  const inventory = mergeInventories([
    { line: "core", inventory: parseConnectorInventory(inventoryFor("irodori-extension-alpha")) },
    {
      line: "lakehouse",
      inventory: parseConnectorInventory(
        inventoryFor("irodori-extension-beta", "irodori-extension-gamma"),
      ),
    },
  ]);
  assert.deepEqual(inventory, {
    owner: "irodori-table",
    lines: ["core", "lakehouse"],
    repositories: [
      { name: "irodori-extension-alpha", line: "core" },
      { name: "irodori-extension-beta", line: "lakehouse" },
      { name: "irodori-extension-gamma", line: "lakehouse" },
    ],
  });
  assert.equal(inventoryBreakdown(inventory), "core 1, lakehouse 2");
});

test("a repository claimed by two registries is an error, not a double audit", () => {
  assert.throws(
    () =>
      mergeInventories([
        { line: "core", inventory: parseConnectorInventory(inventoryFor("irodori-extension-alpha")) },
        {
          line: "lakehouse",
          inventory: parseConnectorInventory(inventoryFor("irodori-extension-alpha")),
        },
      ]),
    /irodori-extension-alpha is listed by both the core and lakehouse registries/,
  );
  assert.throws(() => mergeInventories([]), /no connector registries were read/);
});

test("an unreadable registry fails the audit instead of shrinking the fleet", async () => {
  const registries = [
    { line: "core", url: "registry://core" },
    { line: "lakehouse", url: "registry://lakehouse" },
  ];
  const files = fixture("v0.9.0");
  async function readText(url) {
    if (url === "registry://core") {
      return inventoryFor("irodori-extension-alpha");
    }
    if (url === "registry://lakehouse") {
      throw new Error("HTTP 404");
    }
    return files[
      {
        "Cargo.toml": "cargoToml",
        "Cargo.lock": "cargoLock",
        ".github/workflows/ci.yml": "ciWorkflow",
        ".github/workflows/release.yml": "releaseWorkflow",
      }[url.split("/main/")[1]]
    ];
  }

  await assert.rejects(
    auditFleet({ readText, registries, expectedTag: "v0.9.0" }),
    /lakehouse registry \(registry:\/\/lakehouse\): HTTP 404/,
  );

  // The core line alone still audits clean — which is exactly why a silently
  // dropped registry read as a healthy fleet before.
  const inventory = await readInventory(readText, registries.slice(0, 1));
  assert.deepEqual(inventory.repositories, [
    { name: "irodori-extension-alpha", line: "core" },
  ]);
});

test("a fleet audit spanning both lines reports one tag", async () => {
  const files = fixture("v0.9.0");
  const registries = [
    { line: "core", url: "registry://core" },
    { line: "lakehouse", url: "registry://lakehouse" },
  ];
  const paths = {
    "Cargo.toml": "cargoToml",
    "Cargo.lock": "cargoLock",
    ".github/workflows/ci.yml": "ciWorkflow",
    ".github/workflows/release.yml": "releaseWorkflow",
  };
  async function readText(url) {
    if (url === "registry://core") return inventoryFor("irodori-extension-alpha");
    if (url === "registry://lakehouse") return inventoryFor("irodori-extension-iceberg");
    return files[paths[url.split("/main/")[1]]];
  }

  const { inventory, report } = await auditFleet({
    readText,
    registries,
    expectedTag: "v0.9.0",
  });
  assert.deepEqual(report.errors, []);
  assert.equal(report.tag, "v0.9.0");
  assert.equal(inventory.repositories.length, 2);
  assert.equal(inventoryBreakdown(inventory), "core 1, lakehouse 1");
});
