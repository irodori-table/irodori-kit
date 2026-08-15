#!/usr/bin/env node
/**
 * Fail when a connector declares an authentication method its driver does not
 * implement.
 *
 * `connector.config.json` → `connector.connection.authMethods` is what the
 * catalog, the docs, and (eventually) the connection form read to decide what a
 * connector supports. Nothing checked that the driver agreed, and 161 of the
 * 275 declarations across the fleet turned out to have no implementation behind
 * them — see irodori-table/irodori-table#232.
 *
 * This is a ratchet, not a cliff. `connector-auth-baseline.json` records the
 * debt that already exists so CI stays green today; the check fails on anything
 * that is not in the baseline, in either direction:
 *
 *   - a *new* declaration with no implementation → the gap must be closed, or
 *     the declaration dropped, before merge;
 *   - a baseline entry that *is* now implemented → the baseline is stale and
 *     must shrink, so the debt can only go down.
 *
 * Usage: node check-connector-auth.mjs <manifest-root>
 */
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const BASELINE_PATH = join(HERE, "..", "connector-auth-baseline.json");

/**
 * Identifier fragments whose presence in `driver.rs` counts as evidence that a
 * method is wired up.
 *
 * Deliberately generous: a single matching substring anywhere in the driver is
 * enough. The check is meant to catch declarations with *nothing* behind them,
 * not to audit how well a method is implemented — a false pass is a missed
 * catch, a false fail is a blocked merge, and only one of those is recoverable
 * by the author.
 *
 * `"*"` means the method needs no driver evidence at all.
 */
const EVIDENCE = {
  none: ["*"],
  customDriverOptions: ["*"],
  connectionString: ["connectionString", "dsn", "url"],

  basic: ["password"],
  userPassword: ["password"],
  sqlPassword: ["password"],
  scram: ["password"],
  saslPlain: ["password"],
  saslScram: ["scram", "sasl"],
  srp: ["password"],
  aclUserPassword: ["password"],

  apiKey: ["apiKey", "api_key"],
  jwt: ["jwt"],
  bearerToken: ["bearerToken", "bearer"],
  accessToken: ["accessToken"],
  restToken: ["restToken", "token"],
  redisToken: ["redisToken", "token"],
  pluginToken: ["pluginToken"],
  catalogBearerToken: ["catalogBearerToken", "catalogToken"],
  catalogPassword: ["catalogPassword"],

  // OAuth2 means performing a grant, not accepting a token somebody else
  // obtained. A bare `oauth2` substring credits an option merely *named*
  // `oauth2AccessToken`, which is a bearer token wearing a longer name — so the
  // evidence is the grant machinery: a token endpoint or a client secret.
  //
  // NOT `clientSecret` / `client_secret` either: an Azure service principal
  // uses that name, and crediting it made a connector with no OAuth2 at all
  // look like it had some.
  // `grant_type` is the unambiguous marker: a connector that performs a grant
  // has to name one. bigquery/bigtable/cloud-spanner do (jwt-bearer and
  // refresh_token), iceberg does (client_credentials); elasticsearch, which
  // only forwards a token somebody else obtained, does not.
  oauth2: [
    "grant_type",
    "oauth2ServerUri",
    "oauthServerUri",
    "oauth2ClientSecret",
    "oauthClientSecret",
    "tokenEndpoint",
    "token_endpoint",
  ],
  oauthAccessToken: ["oauthAccessToken"],
  oidc: ["oidc"],
  saml: ["saml"],
  ldap: ["ldap"],
  kerberos: ["kerberos", "gssapi", "krb"],
  externalBrowser: ["externalBrowser", "browser"],
  browserSso: ["browserSso", "browser"],
  windowsIntegrated: ["integratedSecurity", "ntlm", "windowsIntegrated"],
  clientCertificate: [
    "clientCert",
    "client_cert",
    "certPath",
    "sslCert",
    "tlsCert",
  ],
  mongodbX509: ["x509", "X509"],

  awsIam: ["awsIam", "MONGODB-AWS", "awsAccessKey"],
  awsSigV4: ["sigv4", "SigV4", "signRequest", "awsAccessKey"],
  // NOT bare `profile`: every connector contains `request.get("profile")` to
  // find the connection profile, which has nothing to do with an AWS named
  // profile. That one token credited nine connectors for free and hid a real
  // gap in cassandra until the shared helpers moved out of the drivers.
  awsProfile: [
    "awsProfile",
    "AWS_PROFILE",
    "profile_name",
    "from_profile",
    "credentials_file",
  ],
  // NOT bare `sso`: it matched an unrelated substring in a test fixture.
  // `credential_chain` is the real mechanism — DuckDB and the AWS SDK both
  // resolve SSO through it rather than through a named SSO code path.
  awsSso: ["awsSso", "ssoStart", "credential_chain"],
  awsAssumeRole: ["assumeRole", "roleArn", "AssumeRole"],
  awsDefaultCredentialsChain: [
    "defaultCredentialsChain",
    "credentialsChain",
    "credential_chain",
    "awsProfile",
  ],
  // The SDK and DuckDB both reach web identity through the credential chain
  // (the `sts` link), never through a named entry point.
  webIdentity: ["webIdentity", "WebIdentity", "web_identity", "credential_chain"],
  sessionToken: ["sessionToken", "securityToken"],

  serviceAccountJson: ["serviceAccountJson", "credentialsJson"],
  serviceAccountJwt: ["privateKey", "serviceAccountJwt"],
  serviceAccountImpersonation: ["impersonat"],
  googleApplicationDefaultCredentials: [
    "applicationDefault",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "adc",
  ],
  workloadIdentity: ["workloadIdentity", "workload_identity"],

  // The Entra token field names count too. A connector that reads `aadToken`
  // or mints one from a tenant/client pair honours the declared `azureAd`
  // method whether or not it spells the method's own name anywhere.
  azureAd: [
    "azureAd",
    "azure_ad",
    "AzureAD",
    "azureCredentialChain",
    "aadToken",
    "entraToken",
    "azureAccessToken",
    "azureTenantId",
  ],
  servicePrincipal: ["servicePrincipal", "tenantId"],
  servicePrincipalCertificate: [
    "servicePrincipalCertificate",
    "CLIENT_CERTIFICATE_PATH",
  ],
  managedIdentity: ["managedIdentity", "managed_identity"],
  sasToken: ["sasToken"],

  databricksPersonalAccessToken: ["pat", "accessToken"],
  databricksOAuthToken: ["oauthToken"],
  databricksOAuthU2M: ["u2m", "oauthU2M"],
  databricksOAuthM2M: ["m2m", "oauthM2M", "clientSecret"],
  databricksAzureManagedIdentity: ["managedIdentity"],

  snowflakeKeyPair: ["privateKey", "keyPair"],
  snowflakeProgrammaticAccessToken: ["programmaticAccessToken", "pat"],
  snowflakeSessionToken: ["sessionToken"],
  snowflakeWorkloadIdentity: ["workloadIdentity"],

  motherduckToken: ["motherduckToken", "motherduck_token"],
  extensionCredential: ["CREATE SECRET", "createSecret", "credential"],
  oracleWallet: ["wallet"],
  cloudIamToken: ["cloudIamToken", "iamToken"],
};

function fail(message) {
  console.error(`connector-auth: ${message}`);
  process.exit(1);
}

const root = resolve(process.argv[2] ?? ".");
const configPath = join(root, "connector.config.json");
const driverPath = join(root, "src", "driver.rs");

if (!existsSync(configPath)) {
  // Declarative feature extensions carry feature.json instead. Nothing to check.
  console.log("connector-auth: no connector.config.json — skipping");
  process.exit(0);
}

let config;
try {
  config = JSON.parse(readFileSync(configPath, "utf8"));
} catch (error) {
  fail(`connector.config.json is not valid JSON: ${error.message}`);
}

const extensionId = config.extensionId;
if (!extensionId) {
  fail("connector.config.json has no extensionId");
}

const declared = (config.connector?.connection?.authMethods ?? []).map(
  (method) => method.id,
);
if (declared.length === 0) {
  console.log(`connector-auth: ${extensionId} declares no auth methods`);
  process.exit(0);
}

if (!existsSync(driverPath)) {
  fail(
    `${extensionId} declares ${declared.length} auth methods but has no src/driver.rs to implement them`,
  );
}
// Every module, not just driver.rs: iceberg keeps its REST-catalog OAuth2 in
// rest_catalog.rs and hudi its timeline handling in hudi.rs, so reading one
// file judges a connector on a fraction of itself.
const driver = readSources(join(root, "src")).map(stripComments).join("\n");

function readSources(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return readSources(path);
    return entry.name.endsWith(".rs") ? [readFileSync(path, "utf8")] : [];
  });
}

/**
 * Remove Rust comments before looking for evidence.
 *
 * Without this, *writing about* a method marks it implemented: a comment
 * explaining why `kerberos` cannot be supported was itself counted as proof
 * that it was. That is the worst shape of false positive — it rewards
 * discussing auth over doing it, and it would let a real declaration be
 * dropped from the baseline on the strength of a sentence.
 *
 * String literals are kept: option key names live in them and are genuine
 * evidence. So the scanner has to know when it is inside one, or a `//` in a
 * URL would swallow the rest of the line.
 */
function stripComments(source) {
  let out = "";
  let i = 0;
  while (i < source.length) {
    const two = source.slice(i, i + 2);
    if (two === "//") {
      while (i < source.length && source[i] !== "\n") i += 1;
      continue;
    }
    if (two === "/*") {
      i += 2;
      let depth = 1; // Rust block comments nest
      while (i < source.length && depth > 0) {
        if (source.slice(i, i + 2) === "/*") { depth += 1; i += 2; continue; }
        if (source.slice(i, i + 2) === "*/") { depth -= 1; i += 2; continue; }
        i += 1;
      }
      continue;
    }
    if (source[i] === '"') {
      out += source[i];
      i += 1;
      while (i < source.length) {
        if (source[i] === "\\") { out += source.slice(i, i + 2); i += 2; continue; }
        out += source[i];
        if (source[i] === '"') { i += 1; break; }
        i += 1;
      }
      continue;
    }
    out += source[i];
    i += 1;
  }
  return out;
}

const unknown = declared.filter((id) => !(id in EVIDENCE));
if (unknown.length > 0) {
  fail(
    `unknown auth method id(s): ${unknown.join(", ")}. Add them to EVIDENCE in ` +
      `scripts/check-connector-auth.mjs with the driver identifiers that would ` +
      `prove they are implemented.`,
  );
}

const unimplemented = declared.filter((id) => {
  const evidence = EVIDENCE[id];
  return !evidence.includes("*") && !evidence.some((key) => driver.includes(key));
});

const baseline = JSON.parse(readFileSync(BASELINE_PATH, "utf8"));
const allowed = baseline.connectors?.[extensionId] ?? [];

const added = unimplemented.filter((id) => !allowed.includes(id));
const resolved = allowed.filter((id) => !unimplemented.includes(id));

if (added.length > 0) {
  console.error(
    `connector-auth: ${extensionId} declares auth method(s) with no implementation in src/driver.rs:\n` +
      added.map((id) => `  - ${id}`).join("\n") +
      `\n\nImplement them, or drop them from connector.config.json. A declaration\n` +
      `the driver does not honour tells the catalog and the docs this connector\n` +
      `supports something it does not. See irodori-table/irodori-table#232.`,
  );
}

if (resolved.length > 0) {
  console.error(
    `connector-auth: ${extensionId} has baseline entries that are now implemented:\n` +
      resolved.map((id) => `  - ${id}`).join("\n") +
      `\n\nRemove them from connector-auth-baseline.json in irodori-kit so the\n` +
      `remaining debt stays accurate.`,
  );
}

if (added.length > 0 || resolved.length > 0) {
  process.exit(1);
}

const remaining = unimplemented.length;
console.log(
  remaining === 0
    ? `connector-auth: ${extensionId} — all ${declared.length} declared methods have an implementation`
    : `connector-auth: ${extensionId} — ${declared.length - remaining}/${declared.length} implemented, ` +
        `${remaining} known gap(s) in the baseline: ${unimplemented.join(", ")}`,
);
