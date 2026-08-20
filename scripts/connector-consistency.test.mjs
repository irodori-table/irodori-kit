import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { analyzeAuthMethods } from "./lib/connector-auth-evidence.mjs";
import {
  analyzeConnectorFields,
  connectorFieldBinding,
  connectorFieldImplemented,
  declaredConnectorFieldBindings,
  fieldBaselineDiff,
} from "./lib/connector-fields.mjs";
import { stripRustComments } from "./lib/connector-source.mjs";

function config(connection) {
  return { extensionId: "irodori.test", connector: { connection } };
}

test("Rust comment stripping keeps request keys and URLs", () => {
  const source = stripRustComments(`
    // option_string(request, &["commentOnly"])
    let url = "https://example.test/path";
    /* outer /* nested */ option_string(request, &["alsoCommented"]) */
    option_string(request, &["region"]);
  `);
  assert.match(source, /https:\/\/example\.test\/path/);
  assert.match(source, /"region"/);
  assert.doesNotMatch(source, /commentOnly|alsoCommented/);
});

test("auth evidence ignores comments and reports unknown declarations", () => {
  const connection = {
    authMethods: [
      { id: "basic", fields: [] },
      { id: "kerberos", fields: [] },
      { id: "futureMethod", fields: [] },
    ],
  };
  const source = stripRustComments(`
    // kerberos is intentionally unsupported
    option_string(request, &["password"]);
  `);
  assert.deepEqual(analyzeAuthMethods(config(connection), source), {
    declared: ["basic", "kerberos", "futureMethod"],
    unknown: ["futureMethod"],
    unimplemented: ["kerberos"],
  });
});

test("field binding follows option, profileField, then id", () => {
  assert.equal(
    connectorFieldBinding({ id: "id", profileField: "user", option: "UID" }),
    "UID",
  );
  assert.equal(
    connectorFieldBinding({ id: "id", profileField: "password" }),
    "password",
  );
  assert.equal(connectorFieldBinding({ id: "token" }), "token");
});

test("field evidence requires the exact case-sensitive string literal", () => {
  const source = 'let supported = true; option_string(request, &["workgroup"]);';
  assert.equal(connectorFieldImplemented("port", source), false);
  assert.equal(connectorFieldImplemented("WorkGroup", source), false);
  assert.equal(connectorFieldImplemented("workgroup", source), true);
});

test("field collection skips duplicate profile declarations and unimplemented auth", () => {
  const connection = {
    endpoint: {
      fields: [
        { id: "host", profileField: "host" },
        { id: "region", option: "region" },
      ],
    },
    profileFields: [
      { id: "id", profileField: "id" },
      { id: "host", profileField: "host" },
      { id: "region", option: "region" },
      { id: "custom", option: "custom" },
    ],
    authMethods: [
      { id: "basic", fields: [{ id: "password", profileField: "password" }] },
      { id: "kerberos", fields: [{ id: "principal" }] },
    ],
    tls: { supported: true, fields: [{ id: "caCertificate" }] },
  };
  const bindings = declaredConnectorFieldBindings(
    config(connection),
    'option_string(request, &["password"]);',
  ).map(({ binding }) => binding);
  assert.deepEqual(bindings, [
    "caCertificate",
    "custom",
    "host",
    "password",
    "region",
  ]);
});

test("profile duplicate detection matches the host binding rules", () => {
  const connection = {
    endpoint: { fields: [{ id: "endpointUser", profileField: "user" }] },
    profileFields: [{ id: "user", option: "user" }],
    authMethods: [],
    tls: { supported: false, fields: [] },
  };
  const bindings = declaredConnectorFieldBindings(
    config(connection),
    'option_string(request, &["endpointUser"]);',
  );
  assert.deepEqual(bindings, [
    {
      binding: "user",
      origins: ["endpoint.endpointUser", "profile.user"],
    },
  ]);
});

test("analysis and the baseline are bidirectional ratchets", () => {
  const connection = {
    endpoint: {
      fields: [
        { id: "host", profileField: "host" },
        { id: "protocol", option: "protocol" },
      ],
    },
    profileFields: [],
    authMethods: [],
    tls: { supported: false, fields: [] },
  };
  const analysis = analyzeConnectorFields(
    config(connection),
    'option_string(request, &["host"]);',
  );
  assert.deepEqual(
    analysis.missing.map(({ binding }) => binding),
    ["protocol"],
  );
  assert.deepEqual(fieldBaselineDiff(analysis.missing, []).added, analysis.missing);
  assert.deepEqual(fieldBaselineDiff(analysis.missing, ["protocol"]), {
    added: [],
    resolved: [],
  });
  assert.deepEqual(fieldBaselineDiff(analysis.missing, ["obsolete"]).resolved, [
    "obsolete",
  ]);
});

test("connector baselines are sorted and contain no duplicate entries", () => {
  for (const relativePath of [
    "../connector-auth-baseline.json",
    "../connector-field-baseline.json",
  ]) {
    const baseline = JSON.parse(
      readFileSync(new URL(relativePath, import.meta.url), "utf8"),
    );
    const connectorIds = Object.keys(baseline.connectors);
    assert.deepEqual(
      connectorIds,
      [...connectorIds].sort((left, right) => left.localeCompare(right)),
    );
    for (const entries of Object.values(baseline.connectors)) {
      assert.deepEqual(
        entries,
        [...new Set(entries)].sort((left, right) => left.localeCompare(right)),
      );
    }
  }
});
