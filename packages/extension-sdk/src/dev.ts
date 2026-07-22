import type {
  DevLogEntry,
  ExtensionCapabilities,
  ExtensionContributions,
  ExtensionManifest,
  FakeDatabaseFixture,
  PermissionInspection,
  PermissionScope,
} from "./generated/irodori-extension-api.js";

export interface ExtensionDevSession {
  readonly manifest: ExtensionManifest;
  readonly fixtures: readonly FakeDatabaseFixture[];
  readonly permissions: PermissionInspection;
  readonly logs: readonly DevLogEntry[];
}

export interface ExtensionDevHost {
  reload(reason: string): Promise<void>;
  inspectPermissions(manifest: ExtensionManifest): PermissionInspection;
  loadFixtures(manifest: ExtensionManifest): Promise<readonly FakeDatabaseFixture[]>;
  readLogs(): Promise<readonly DevLogEntry[]>;
}

export const sensitivePermissionScopes: readonly PermissionScope[] = [
  "hostFeatures",
  "connections:write",
  "connectors",
  "queries:run",
  "queryResults:read",
  "queryResults:write",
  "files:write",
  "native",
  "wasm",
];

type PermissionInspectableManifest = Pick<ExtensionManifest, "permissions"> &
  Partial<Pick<ExtensionManifest, "contributes" | "capabilities">>;

type ContributionKey = keyof ExtensionContributions;
type CapabilityKey = keyof ExtensionCapabilities;

interface PermissionRequirementRule<TKey extends string> {
  readonly key: TKey;
  readonly permission: PermissionScope;
  readonly message: string;
}

const contributionPermissionRules: readonly PermissionRequirementRule<ContributionKey>[] = [
  {
    key: "hostFeatures",
    permission: "hostFeatures",
    message: "contributes.hostFeatures requires permissions: hostFeatures",
  },
  {
    key: "commands",
    permission: "commands",
    message: "contributes.commands requires permissions: commands",
  },
  {
    key: "keybindings",
    permission: "keybindings",
    message: "contributes.keybindings requires permissions: keybindings",
  },
  {
    key: "resultGridActions",
    permission: "resultRenderers",
    message: "contributes.resultGridActions requires permissions: resultRenderers",
  },
  {
    key: "resultGridRenderers",
    permission: "resultRenderers",
    message: "contributes.resultGridRenderers requires permissions: resultRenderers",
  },
  {
    key: "statusBarItems",
    permission: "statusBar",
    message: "contributes.statusBarItems requires permissions: statusBar",
  },
  {
    key: "themes",
    permission: "themes",
    message: "contributes.themes requires permissions: themes",
  },
  {
    key: "sqlDialects",
    permission: "sqlDialects",
    message: "contributes.sqlDialects requires permissions: sqlDialects",
  },
  {
    key: "connectors",
    permission: "connectors",
    message: "contributes.connectors requires permissions: connectors",
  },
];

const capabilityPermissionRules: readonly PermissionRequirementRule<CapabilityKey>[] = [
  {
    key: "wasmModules",
    permission: "wasm",
    message: "capabilities.wasmModules requires permissions: wasm",
  },
  {
    key: "nativeModules",
    permission: "native",
    message: "capabilities.nativeModules requires permissions: native",
  },
];

export function inspectManifestPermissions(
  manifest: PermissionInspectableManifest,
  permissions: readonly PermissionScope[] = manifest.permissions,
): PermissionInspection {
  const declared = uniquePermissionScopes(permissions);
  const declaredSet = new Set(declared);

  return {
    declared,
    sensitive: declared.filter(isSensitivePermissionScope),
    missingForContributions: missingPermissionMessages(manifest, declaredSet),
  };
}

export function isSensitivePermissionScope(scope: PermissionScope): boolean {
  return sensitivePermissionScopes.includes(scope);
}

export function formatPermissionWarnings(inspection: PermissionInspection): string[] {
  return inspection.missingForContributions.map((missing) => `permission warning: ${missing}`);
}

function missingPermissionMessages(
  manifest: PermissionInspectableManifest,
  declared: ReadonlySet<PermissionScope>,
): string[] {
  const contributes: Partial<ExtensionContributions> = manifest.contributes ?? {};
  const capabilities: Partial<ExtensionCapabilities> = manifest.capabilities ?? {};
  const contributionMessages = contributionPermissionRules.flatMap((rule) =>
    hasItems(contributes[rule.key]) && !declared.has(rule.permission) ? [rule.message] : [],
  );
  const capabilityMessages = capabilityPermissionRules.flatMap((rule) =>
    hasItems(capabilities[rule.key]) && !declared.has(rule.permission) ? [rule.message] : [],
  );

  return [...contributionMessages, ...capabilityMessages];
}

function uniquePermissionScopes(permissions: readonly PermissionScope[]): PermissionScope[] {
  return [...new Set(permissions)];
}

function hasItems(value: unknown): boolean {
  return Array.isArray(value) && value.length > 0;
}
