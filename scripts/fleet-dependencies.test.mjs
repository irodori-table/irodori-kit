import assert from "node:assert/strict";
import test from "node:test";
import {
  inspectConnector,
  inspectFleet,
  parseConnectorInventory,
  rawRepositoryFileUrl,
  workspaceTag,
} from "./check-fleet-dependencies.mjs";

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
