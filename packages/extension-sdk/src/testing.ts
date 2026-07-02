import type {
  ConnectorContribution,
  DevLogEntry,
  DevLogLevel,
  ExtensionManifest,
  FakeDatabaseFixture,
  KeybindingContribution,
  PermissionScope,
  ResultGridActionContribution,
  ResultGridCell,
  ResultGridColumn,
  ResultGridRow,
  ResultGridSelection,
  ResultGridSnapshot,
  SqlDialectDefinition,
  StatusBarItemContribution,
  ThemeDefinition,
} from "./generated/irodori-extension-api.js";
import { inspectManifestPermissions } from "./dev.js";
import type { CommandHandler, Disposable, ExtensionContext } from "./index.js";

export interface ExtensionTestContextOptions {
  readonly manifest: ExtensionManifest;
  readonly extensionPath?: string;
  readonly permissions?: readonly PermissionScope[];
  readonly resultGridSnapshot?: ResultGridSnapshot;
  readonly resultGridSelection?: ResultGridSelection;
  readonly now?: () => Date;
}

export interface RegisteredResultGridAction {
  readonly action: ResultGridActionContribution;
  readonly handler: CommandHandler;
}

export interface ExtensionTestContext {
  readonly context: ExtensionContext;
  readonly logs: readonly DevLogEntry[];
  readonly copiedText: readonly string[];
  readonly commands: ReadonlyMap<string, CommandHandler>;
  readonly keybindings: readonly KeybindingContribution[];
  readonly resultGridActions: readonly RegisteredResultGridAction[];
  readonly themes: readonly ThemeDefinition[];
  readonly sqlDialects: readonly SqlDialectDefinition[];
  readonly connectors: readonly ConnectorContribution[];
  readonly statusBarItems: readonly StatusBarItemContribution[];
  setActiveResultGridSnapshot(snapshot: ResultGridSnapshot | undefined): void;
  setResultGridSelection(selection: ResultGridSelection | undefined): void;
  dispose(): void;
}

export function createFakeDatabase(fixture: FakeDatabaseFixture): FakeDatabaseFixture {
  return fixture;
}

export function createExtensionTestContext(
  options: ExtensionTestContextOptions,
): ExtensionTestContext {
  const commandHandlers = new Map<string, CommandHandler>();
  const keybindings: KeybindingContribution[] = [];
  const resultGridActions: RegisteredResultGridAction[] = [];
  const themes: ThemeDefinition[] = [];
  const sqlDialects: SqlDialectDefinition[] = [];
  const connectors: ConnectorContribution[] = [];
  const statusBarItems: StatusBarItemContribution[] = [];
  const subscriptions: Disposable[] = [];
  const copiedText: string[] = [];
  const logs: DevLogEntry[] = [];
  const permissions = new Set(options.permissions ?? options.manifest.permissions);
  const now = options.now ?? (() => new Date());
  let activeSnapshot = options.resultGridSnapshot;
  let activeSelection = options.resultGridSelection;

  const context: ExtensionContext = {
    manifest: options.manifest,
    extensionPath: options.extensionPath ?? ".",
    subscriptions,
    commands: {
      registerCommand(id, handler) {
        commandHandlers.set(id, handler as CommandHandler);
        return disposable(() => {
          if (commandHandlers.get(id) === handler) {
            commandHandlers.delete(id);
          }
        });
      },
      async executeCommand(id, ...args) {
        const handler = commandHandlers.get(id);
        if (!handler) {
          throw new Error(`Command is not registered: ${id}`);
        }
        return (await handler(...args)) as never;
      },
    },
    keybindings: {
      registerKeybinding(keybinding) {
        keybindings.push(keybinding);
        return removeFromArrayOnDispose(keybindings, keybinding);
      },
    },
    resultGrid: {
      async getActiveSnapshot() {
        return activeSnapshot;
      },
      async getSelection() {
        return activeSelection ?? activeSnapshot?.selection;
      },
      registerAction(action, handler) {
        const registered = { action, handler: handler as CommandHandler };
        resultGridActions.push(registered);
        return removeFromArrayOnDispose(resultGridActions, registered);
      },
      async copyText(text) {
        copiedText.push(text);
      },
    },
    themes: {
      registerTheme(theme) {
        themes.push(theme);
        return removeFromArrayOnDispose(themes, theme);
      },
    },
    sqlDialects: {
      registerDialect(dialect) {
        sqlDialects.push(dialect);
        return removeFromArrayOnDispose(sqlDialects, dialect);
      },
    },
    connectors: {
      registerConnector(connector) {
        connectors.push(connector);
        return removeFromArrayOnDispose(connectors, connector);
      },
    },
    statusBar: {
      registerItem(item) {
        statusBarItems.push(item);
        return removeFromArrayOnDispose(statusBarItems, item);
      },
    },
    permissions: {
      has(scope) {
        return permissions.has(scope);
      },
      require(scope) {
        if (!permissions.has(scope)) {
          throw new Error(`Missing extension permission: ${scope}`);
        }
      },
      inspect() {
        return inspectManifestPermissions(options.manifest, [...permissions]);
      },
    },
    log: {
      debug: (message, data) => appendLog(logs, now, "debug", options.manifest.id, message, data),
      info: (message, data) => appendLog(logs, now, "info", options.manifest.id, message, data),
      warn: (message, data) => appendLog(logs, now, "warn", options.manifest.id, message, data),
      error: (message, data) => appendLog(logs, now, "error", options.manifest.id, message, data),
    },
  };

  return {
    context,
    logs,
    copiedText,
    commands: commandHandlers,
    keybindings,
    resultGridActions,
    themes,
    sqlDialects,
    connectors,
    statusBarItems,
    setActiveResultGridSnapshot(snapshot) {
      activeSnapshot = snapshot;
    },
    setResultGridSelection(selection) {
      activeSelection = selection;
    },
    dispose() {
      for (let index = subscriptions.length - 1; index >= 0; index -= 1) {
        subscriptions[index]?.dispose();
      }
      subscriptions.length = 0;
      commandHandlers.clear();
      keybindings.length = 0;
      resultGridActions.length = 0;
      themes.length = 0;
      sqlDialects.length = 0;
      connectors.length = 0;
      statusBarItems.length = 0;
    },
  };
}

export function createResultGridSnapshot(
  columns: readonly ResultGridColumn[],
  rows: readonly Record<string, unknown>[],
  options: Pick<ResultGridSnapshot, "selection" | "truncated"> = { truncated: false },
): ResultGridSnapshot {
  return {
    columns: [...columns],
    rows: rows.map(
      (row, rowIndex): ResultGridRow => ({
        rowIndex,
        cells: columns.map(
          (column): ResultGridCell => ({
            column: column.name,
            value: row[column.name],
          }),
        ),
      }),
    ),
    selection: options.selection,
    truncated: options.truncated,
  };
}

export function formatResultGridAsMarkdown(snapshot: ResultGridSnapshot): string {
  const columnNames = snapshot.columns.map((column) => column.name);
  const headers = columnNames.map(escapeMarkdownCell);
  const divider = headers.map(() => "---");
  const rows = snapshot.rows.map((row) =>
    columnNames.map((column) => escapeMarkdownCell(cellValue(row, column))),
  );

  return [headers, divider, ...rows].map((cells) => `| ${cells.join(" | ")} |`).join("\n");
}

function cellValue(row: ResultGridRow, column: string): string {
  const value = row.cells.find((cell) => cell.column === column)?.value;
  if (value === null || value === undefined) {
    return "";
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

function escapeMarkdownCell(value: string): string {
  return value.replaceAll("|", "\\|").replaceAll("\n", "<br>");
}

function disposable(dispose: () => void): Disposable {
  let disposed = false;

  return {
    dispose() {
      if (disposed) {
        return;
      }
      disposed = true;
      dispose();
    },
  };
}

function removeFromArrayOnDispose<T>(values: T[], value: T): Disposable {
  return disposable(() => {
    const index = values.indexOf(value);
    if (index >= 0) {
      values.splice(index, 1);
    }
  });
}

function appendLog(
  logs: DevLogEntry[],
  now: () => Date,
  level: DevLogLevel,
  target: string,
  message: string,
  data: unknown,
): void {
  logs.push({
    level,
    message: data === undefined ? message : `${message} ${stringifyLogData(data)}`,
    target,
    timestamp: now().toISOString(),
  });
}

function stringifyLogData(data: unknown): string {
  if (data instanceof Error) {
    return data.message;
  }
  try {
    return JSON.stringify(data);
  } catch {
    return String(data);
  }
}
