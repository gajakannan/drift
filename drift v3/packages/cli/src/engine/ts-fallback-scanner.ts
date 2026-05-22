import { readdirSync } from "node:fs";
import { join,relative } from "node:path";

export function walkIndexableFiles(repoRoot: string): string[] {
  const files: string[] = [];
  const visit = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (shouldSkipPath(entry.name)) {
        continue;
      }

      const absolutePath = join(dir, entry.name);
      if (entry.isDirectory()) {
        visit(absolutePath);
      } else if (entry.isFile() && isTypescriptPath(entry.name)) {
        files.push(relative(repoRoot, absolutePath).replaceAll("\\", "/"));
      }
    }
  };
  visit(repoRoot);
  return files.sort();
}

export function shouldSkipPath(name: string): boolean {
  return [
    ".git",
    "node_modules",
    "dist",
    "build",
    "coverage",
    ".next",
    "target",
    "vendor"
  ].includes(name);
}

export function isTypescriptPath(filePath: string): boolean {
  return /\.[cm]?[jt]sx?$/.test(filePath);
}
