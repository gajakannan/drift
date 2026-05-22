import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname,join } from "node:path";
import { fileURLToPath } from "node:url";

export function runRustEngine(args: string[]): string | undefined {
  const explicit = process.env.DRIFT_ENGINE_BIN;
  if (explicit) {
    return execFileSync(explicit, args, { encoding: "utf8" });
  }

  const workspaceRoot = findCargoWorkspaceRoot();
  if (!workspaceRoot) {
    return undefined;
  }

  try {
    return execFileSync("cargo", ["run", "--quiet", "-p", "drift-engine", "--", ...args], {
      cwd: workspaceRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    });
  } catch {
    return undefined;
  }
}

export function findCargoWorkspaceRoot(): string | undefined {
  let current = dirname(fileURLToPath(import.meta.url));
  while (current !== dirname(current)) {
    if (existsSync(join(current, "Cargo.toml")) && existsSync(join(current, "crates", "drift-engine"))) {
      return current;
    }
    current = dirname(current);
  }
  return undefined;
}
