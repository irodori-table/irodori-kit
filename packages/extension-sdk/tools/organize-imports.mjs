#!/usr/bin/env node
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { relative, resolve } from "node:path";
import ts from "typescript";

const root = resolve(import.meta.dirname, "..");
const options = parseArgs(process.argv.slice(2));
const files = collectInputFiles(options.paths);

if (files.length === 0) {
  console.log("organize-imports: no TypeScript files found");
  process.exit(0);
}

const snapshots = new Map(files.map((file) => [file, readFileSync(file, "utf8")]));
const versions = new Map(files.map((file) => [file, "0"]));
const service = ts.createLanguageService({
  getScriptFileNames: () => files,
  getScriptVersion: (fileName) => versions.get(fileName) ?? "0",
  getScriptSnapshot: (fileName) => {
    const source = snapshots.get(fileName) ?? ts.sys.readFile(fileName);
    return source === undefined ? undefined : ts.ScriptSnapshot.fromString(source);
  },
  getCurrentDirectory: () => root,
  getCompilationSettings: () => ({
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    strict: true,
    skipLibCheck: true,
    verbatimModuleSyntax: true,
  }),
  getDefaultLibFileName: ts.getDefaultLibFilePath,
  fileExists: ts.sys.fileExists,
  readFile: ts.sys.readFile,
  readDirectory: ts.sys.readDirectory,
  directoryExists: ts.sys.directoryExists,
  getDirectories: ts.sys.getDirectories,
  realpath: ts.sys.realpath,
  useCaseSensitiveFileNames: () => ts.sys.useCaseSensitiveFileNames,
  getNewLine: () => "\n",
});
const formatOptions = {
  convertTabsToSpaces: true,
  indentSize: 2,
  insertSpaceAfterCommaDelimiter: true,
  insertSpaceAfterOpeningAndBeforeClosingNonemptyBraces: true,
  insertSpaceBeforeAndAfterBinaryOperators: true,
  newLineCharacter: "\n",
  semicolons: ts.SemicolonPreference.Insert,
  tabSize: 2,
};

const changed = [];

for (const file of files) {
  const source = snapshots.get(file);
  if (source === undefined) {
    continue;
  }
  const changes = service.organizeImports(
    {
      type: "file",
      fileName: file,
      mode: ts.OrganizeImportsMode.RemoveUnused,
    },
    formatOptions,
    {},
  );
  const updated = applyTextChanges(source, changes.flatMap((change) => change.textChanges));
  if (updated !== source) {
    changed.push(file);
    if (!options.check) {
      writeFileSync(file, updated);
      snapshots.set(file, updated);
      versions.set(file, String(Number(versions.get(file) ?? "0") + 1));
    }
  }
}

if (options.check && changed.length > 0) {
  console.error("organize-imports: unused imports found:");
  for (const file of changed) {
    console.error(`  ${relative(root, file)}`);
  }
  console.error("Run `npm run fix:imports`.");
  process.exit(1);
}

console.log(
  options.check
    ? `organize-imports: ok (${files.length} files)`
    : `organize-imports: updated ${changed.length} of ${files.length} files`,
);

function parseArgs(args) {
  const parsed = {
    check: false,
    paths: [],
  };

  for (const arg of args) {
    if (arg === "--check" || arg === "-c") {
      parsed.check = true;
      continue;
    }
    if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    }
    if (arg.startsWith("-")) {
      console.error(`Unknown argument: ${arg}`);
      printHelp();
      process.exit(1);
    }
    parsed.paths.push(resolve(process.cwd(), arg));
  }

  return parsed;
}

function printHelp() {
  console.log(
    [
      "Usage: node tools/organize-imports.mjs [--check] [path...]",
      "",
      "Removes unused imports from TypeScript files using the TypeScript language service.",
      "When no path is provided, src and templates are scanned.",
      "",
      "Options:",
      "  --check, -c   Fail if any file would change.",
      "  --help, -h    Show this help.",
    ].join("\n"),
  );
}

function collectInputFiles(paths) {
  const roots = paths.length > 0 ? paths : [resolve(root, "src"), resolve(root, "templates")];
  const results = [];

  for (const path of roots) {
    collectTypeScriptFiles(path, results);
  }

  return [...new Set(results)].sort();
}

function collectTypeScriptFiles(path, results) {
  if (!existsSync(path)) {
    return;
  }
  const stat = statSync(path);
  if (stat.isFile()) {
    if (path.endsWith(".ts") && !path.endsWith(".d.ts") && !path.includes("/generated/")) {
      results.push(path);
    }
    return;
  }
  if (!stat.isDirectory()) {
    return;
  }
  const name = path.split(/[\\/]/).at(-1);
  if (name === "node_modules" || name === "dist" || name === "generated") {
    return;
  }
  for (const entry of readdirSync(path)) {
    collectTypeScriptFiles(resolve(path, entry), results);
  }
}

function applyTextChanges(source, changes) {
  return [...changes]
    .sort((left, right) => right.span.start - left.span.start)
    .reduce(
      (next, change) =>
        next.slice(0, change.span.start) +
        change.newText +
        next.slice(change.span.start + change.span.length),
      source,
    );
}
