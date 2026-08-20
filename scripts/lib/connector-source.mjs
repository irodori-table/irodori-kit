import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

/** Read every Rust source file below a connector's src directory. */
export function readRustSources(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      return readRustSources(path);
    }
    return entry.name.endsWith(".rs") ? [readFileSync(path, "utf8")] : [];
  });
}

/**
 * Remove Rust comments while retaining string literals, where request keys and
 * implementation evidence live. Rust block comments may nest.
 */
export function stripRustComments(source) {
  let out = "";
  let i = 0;
  while (i < source.length) {
    const two = source.slice(i, i + 2);
    if (two === "//") {
      while (i < source.length && source[i] !== "\n") {
        i += 1;
      }
      continue;
    }
    if (two === "/*") {
      i += 2;
      let depth = 1;
      while (i < source.length && depth > 0) {
        if (source.slice(i, i + 2) === "/*") {
          depth += 1;
          i += 2;
          continue;
        }
        if (source.slice(i, i + 2) === "*/") {
          depth -= 1;
          i += 2;
          continue;
        }
        i += 1;
      }
      continue;
    }
    if (source[i] === '"') {
      out += source[i];
      i += 1;
      while (i < source.length) {
        if (source[i] === "\\") {
          out += source.slice(i, i + 2);
          i += 2;
          continue;
        }
        out += source[i];
        if (source[i] === '"') {
          i += 1;
          break;
        }
        i += 1;
      }
      continue;
    }
    out += source[i];
    i += 1;
  }
  return out;
}

/** The comment-free Rust implementation surface used by both CI ratchets. */
export function connectorRustSource(srcDir) {
  return readRustSources(srcDir).map(stripRustComments).join("\n");
}
