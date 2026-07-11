#!/usr/bin/env node

import { cpSync, existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { basename, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const options = parseArgs(process.argv.slice(2));
const root = resolve(options.root ?? process.cwd());
const manifest = readJson(resolve(root, "irodori.extension.json"));
const config = readJson(resolve(root, "connector.config.json"));
const crateName = requiredLibraryName(
  requiredString(config.runtime?.crate, "runtime.crate"),
  "runtime.crate",
);
const targetLabel = currentTargetLabel();
const targetDir = resolve(
  process.env.CARGO_TARGET_DIR || resolve(root, "target"),
);
const releaseDir = resolve(targetDir, "release");
const nativeDir = resolve(root, "dist/native");
const archiveName = `${basename(root)}-${targetLabel}.tar.gz`;
const archivePath = resolve(root, "dist", archiveName);
const archiveRelativePath = `dist/${archiveName}`;

rmSync(nativeDir, { force: true, recursive: true });
mkdirSync(nativeDir, { recursive: true });
copyRequiredLibrary(crateName);
for (const library of options.includeLibraries) {
  copyRequiredLibrary(requiredLibraryName(library, "--include-library"));
}

mkdirSync(resolve(root, "dist"), { recursive: true });
rmSync(archivePath, { force: true });
const archiveEntries = [
  "README.md",
  "LICENSE-0BSD",
  "LICENSE-MIT",
  "connector.config.json",
  "connector.source.json",
  "irodori.extension.json",
  "dist/native",
];
for (const entry of archiveEntries) {
  if (!existsSync(resolve(root, entry))) {
    throw new Error(`required package entry is missing: ${entry}`);
  }
}
run("tar", ["-czf", archiveRelativePath, ...archiveEntries], root);

console.log(
  JSON.stringify(
    {
      extensionId: manifest.id,
      version: manifest.version,
      target: targetLabel,
      archive: archivePath,
    },
    null,
    2,
  ),
);

function copyRequiredLibrary(name) {
  const fileName = dynamicLibraryName(name);
  const candidates = [
    resolve(releaseDir, fileName),
    resolve(releaseDir, "deps", fileName),
  ];
  const source = candidates.find(existsSync);
  if (!source) {
    throw new Error(
      `native library ${fileName} was not found in ${releaseDir} or ${resolve(releaseDir, "deps")}`,
    );
  }
  cpSync(source, resolve(nativeDir, fileName));
}

function dynamicLibraryName(name) {
  if (process.platform === "win32") {
    return `${name}.dll`;
  }
  if (process.platform === "darwin") {
    return `lib${name}.dylib`;
  }
  return `lib${name}.so`;
}

function currentTargetLabel() {
  const arch =
    process.arch === "x64"
      ? "x86_64"
      : process.arch === "arm64"
        ? "aarch64"
        : process.arch;
  const platform =
    process.platform === "win32"
      ? "windows"
      : process.platform === "darwin"
        ? "macos"
        : process.platform;
  if (!/^(x86_64|aarch64)-(linux|macos|windows)$/.test(`${arch}-${platform}`)) {
    throw new Error(`unsupported native release target: ${arch}-${platform}`);
  }
  return `${arch}-${platform}`;
}

function parseArgs(args) {
  const parsed = { root: null, includeLibraries: [] };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--root") {
      parsed.root = requiredArg(args[index + 1], arg);
      index += 1;
      continue;
    }
    if (arg === "--include-library") {
      parsed.includeLibraries.push(requiredArg(args[index + 1], arg));
      index += 1;
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }
  return parsed;
}

function requiredArg(value, option) {
  if (!value || value.startsWith("--")) {
    throw new Error(`${option} requires a value`);
  }
  return value;
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function requiredString(value, label) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${label} is required`);
  }
  return value;
}

function requiredLibraryName(value, label) {
  if (!/^[A-Za-z0-9_]+$/.test(value)) {
    throw new Error(`${label} must contain only letters, numbers, or underscores`);
  }
  return value;
}

function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, encoding: "utf8" });
  if (result.status !== 0) {
    process.stderr.write(result.stdout ?? "");
    process.stderr.write(result.stderr ?? "");
    throw new Error(`${command} exited with status ${result.status}`);
  }
}
