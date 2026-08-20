import { analyzeAuthMethods, authMethodImplemented } from "./connector-auth-evidence.mjs";

// These first-class profile values are owned by the host UI/runtime. Their
// repeated entries in profileFields do not create a second driver obligation;
// endpoint/auth sections below carry the connector-facing declarations.
const HOST_PROFILE_FIELDS = new Set([
  "id",
  "url",
  "host",
  "port",
  "database",
  "socketPath",
  "readOnly",
]);
const AUTH_PROFILE_FIELDS = new Set(["user", "password"]);

export function connectorFieldBinding(field) {
  for (const value of [field?.option, field?.profileField, field?.id]) {
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return null;
}

function fieldIdentity(field) {
  return typeof field?.id === "string" ? field.id : null;
}

function fieldOptionKey(field) {
  if (typeof field?.option === "string" && field.option.trim()) {
    return field.option.trim();
  }
  if (typeof field?.profileField === "string" && field.profileField.trim()) {
    return null;
  }
  return fieldIdentity(field);
}

function sameDeclaredField(left, right) {
  const leftId = fieldIdentity(left);
  const rightId = fieldIdentity(right);
  if (leftId && rightId && leftId === rightId) {
    return true;
  }
  if (
    typeof left?.profileField === "string" &&
    typeof right?.profileField === "string" &&
    left.profileField === right.profileField
  ) {
    return true;
  }
  const leftOption = fieldOptionKey(left);
  const rightOption = fieldOptionKey(right);
  return Boolean(leftOption && rightOption && leftOption === rightOption);
}

function fieldOrigin(section, field, methodId = null) {
  const id = fieldIdentity(field) ?? "<invalid>";
  return methodId ? `${section}.${methodId}.${id}` : `${section}.${id}`;
}

/**
 * Return the concrete request keys a connector promises to consume.
 *
 * Authentication fields are checked only when the existing method-level
 * ratchet sees that method as implemented. Otherwise connector-auth-baseline
 * owns the debt and this guard would only duplicate it one field at a time.
 */
export function declaredConnectorFieldBindings(config, source) {
  const connection = config.connector?.connection ?? {};
  const endpointFields = connection.endpoint?.fields ?? [];
  const authMethods = connection.authMethods ?? [];
  const tlsFields = connection.tls?.supported
    ? (connection.tls.fields ?? [])
    : [];
  const sectionFields = [
    ...endpointFields,
    ...authMethods.flatMap((method) => method.fields ?? []),
    ...tlsFields,
  ];
  const candidates = [];

  for (const field of endpointFields) {
    candidates.push({ field, origin: fieldOrigin("endpoint", field) });
  }
  for (const method of authMethods) {
    if (authMethodImplemented(method.id, source) !== true) {
      continue;
    }
    for (const field of method.fields ?? []) {
      candidates.push({
        field,
        origin: fieldOrigin("auth", field, method.id),
      });
    }
  }
  for (const field of tlsFields) {
    candidates.push({ field, origin: fieldOrigin("tls", field) });
  }

  // Match the app's supplemental-profile-field rule. The generated manifests
  // repeat endpoint/auth/TLS fields in profileFields; checking both would make
  // one runtime key look like two independent obligations.
  for (const field of connection.profileFields ?? []) {
    if (
      field.profileField &&
      (HOST_PROFILE_FIELDS.has(field.profileField) ||
        (authMethods.length > 0 && AUTH_PROFILE_FIELDS.has(field.profileField)))
    ) {
      continue;
    }
    if (sectionFields.some((sectionField) => sameDeclaredField(field, sectionField))) {
      continue;
    }
    candidates.push({ field, origin: fieldOrigin("profile", field) });
  }

  const bindings = new Map();
  for (const candidate of candidates) {
    const binding = connectorFieldBinding(candidate.field);
    if (!binding || binding === "options") {
      continue;
    }
    const origins = bindings.get(binding) ?? [];
    if (!origins.includes(candidate.origin)) {
      origins.push(candidate.origin);
    }
    bindings.set(binding, origins);
  }
  return [...bindings.entries()]
    .map(([binding, origins]) => ({ binding, origins: origins.sort() }))
    .sort((left, right) => left.binding.localeCompare(right.binding));
}

/**
 * Connector request keys are case-sensitive JSON object keys. Requiring their
 * exact Rust string literal avoids crediting `port` for an unrelated identifier
 * such as `supported`, and catches case drift such as WorkGroup/workgroup.
 */
export function connectorFieldImplemented(binding, source) {
  return source.includes(JSON.stringify(binding));
}

export function analyzeConnectorFields(config, source) {
  const auth = analyzeAuthMethods(config, source);
  const declared = declaredConnectorFieldBindings(config, source);
  const missing = declared.filter(
    ({ binding }) => !connectorFieldImplemented(binding, source),
  );
  return { auth, declared, missing };
}

export function fieldBaselineDiff(missing, allowed) {
  const missingBindings = missing.map(({ binding }) => binding);
  return {
    added: missing.filter(({ binding }) => !allowed.includes(binding)),
    resolved: allowed.filter((binding) => !missingBindings.includes(binding)),
  };
}
