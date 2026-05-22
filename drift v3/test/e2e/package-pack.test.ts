import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const tempDirs: string[] = [];

interface PackedPackage {
  manifest: {
    name: string;
    version: string;
    description?: string;
    license?: string;
    bin?: Record<string, string>;
    exports?: Record<string, { types?: string; import?: string }>;
    dependencies?: Record<string, string>;
    engines?: Record<string, string>;
    scripts?: Record<string, string>;
  };
  files: string[];
  tarballPath: string;
}

async function packWorkspacePackage(packageDir: string): Promise<PackedPackage> {
  const dir = await mkdtemp(join(tmpdir(), "drift-pack-"));
  tempDirs.push(dir);
  const packed = await execFileAsync("pnpm", [
    "--dir", packageDir,
    "pack",
    "--json",
    "--pack-destination", dir
  ]);
  const packResult = parsePnpmPackJson(packed.stdout);
  const extractDir = join(dir, "extract");
  await execFileAsync("mkdir", ["-p", extractDir]);
  await execFileAsync("tar", ["-xzf", packResult.filename, "-C", extractDir]);
  const listed = await execFileAsync("find", [join(extractDir, "package"), "-type", "f"]);
  const packageRoot = join(extractDir, "package");
  const files = listed.stdout
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((filePath) => filePath.slice(packageRoot.length + 1))
    .sort();
  const manifest = JSON.parse(await readFile(join(packageRoot, "package.json"), "utf8"));
  return { manifest, files, tarballPath: packResult.filename };
}

function parsePnpmPackJson(stdout: string): { filename: string } {
  const prettyJsonIndex = stdout.lastIndexOf("{\n  \"name\"");
  const compactJsonIndex = stdout.lastIndexOf("{\"name\"");
  const index = Math.max(prettyJsonIndex, compactJsonIndex);
  if (index < 0) {
    throw new Error(`Unable to parse pnpm pack JSON output:\n${stdout}`);
  }
  return JSON.parse(stdout.slice(index)) as { filename: string };
}

function expectDistOnly(files: string[]): void {
  expect(files.every((file) =>
    file === "package.json" ||
    file === "README.md" ||
    file.startsWith("dist/")
  )).toBe(true);
  expect(files.some((file) => file.startsWith("src/"))).toBe(false);
  expect(files.some((file) => file.startsWith("test/"))).toBe(false);
  expect(files).not.toContain("tsconfig.json");
}

function expectPackageMetadata(manifest: PackedPackage["manifest"]): void {
  expect(manifest.version).toBe("0.1.0");
  expect(manifest.description).toBeTruthy();
  expect(manifest.license).toBe("UNLICENSED");
  expect(manifest.engines?.node).toBe(">=20.0.0");
}

function expectNoWorkspaceDependencies(manifest: PackedPackage["manifest"]): void {
  expect(Object.values(manifest.dependencies ?? {}).some((version) => version.startsWith("workspace:"))).toBe(false);
}

async function packAllWorkspacePackages(): Promise<Record<string, PackedPackage>> {
  const packages = await Promise.all([
    packWorkspacePackage("packages/core"),
    packWorkspacePackage("packages/storage"),
    packWorkspacePackage("packages/cli"),
    packWorkspacePackage("packages/mcp")
  ]);
  return Object.fromEntries(packages.map((packed) => [packed.manifest.name, packed]));
}

async function expectSourcePrepack(packageDir: string): Promise<void> {
  const manifest = JSON.parse(await readFile(join(packageDir, "package.json"), "utf8"));
  expect(manifest.scripts?.prepack).toBe("pnpm build");
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("packed Drift workspace packages", () => {
  it("packs @drift/core as a dist-only runtime package", async () => {
    const packed = await packWorkspacePackage("packages/core");

    await expectSourcePrepack("packages/core");
    expect(packed.manifest.name).toBe("@drift/core");
    expectPackageMetadata(packed.manifest);
    expect(packed.manifest.exports?.["."]?.import).toBe("./dist/index.js");
    expect(packed.files).toContain("dist/index.js");
    expect(packed.files).toContain("dist/index.d.ts");
    expect(packed.files).toContain("README.md");
    expectDistOnly(packed.files);
  }, 30000);

  it("packs @drift/storage as a dist-only runtime package without workspace dependency protocols", async () => {
    const packed = await packWorkspacePackage("packages/storage");

    await expectSourcePrepack("packages/storage");
    expect(packed.manifest.name).toBe("@drift/storage");
    expectPackageMetadata(packed.manifest);
    expect(packed.manifest.exports?.["."]?.import).toBe("./dist/index.js");
    expect(packed.files).toContain("dist/index.js");
    expect(packed.files).toContain("dist/index.d.ts");
    expect(packed.files).toContain("README.md");
    expectDistOnly(packed.files);
    expectNoWorkspaceDependencies(packed.manifest);
  }, 30000);

  it("packs @drift/cli with only dist files and a compiled drift bin", async () => {
    const packed = await packWorkspacePackage("packages/cli");

    await expectSourcePrepack("packages/cli");
    expect(packed.manifest.name).toBe("@drift/cli");
    expectPackageMetadata(packed.manifest);
    expect(packed.manifest.bin?.drift).toBe("./dist/main.js");
    expect(packed.manifest.exports?.["."]?.import).toBe("./dist/index.js");
    expect(packed.files).toContain("dist/main.js");
    expect(packed.files).toContain("dist/index.d.ts");
    expect(packed.files).toContain("README.md");
    expectDistOnly(packed.files);
    expectNoWorkspaceDependencies(packed.manifest);
  }, 30000);

  it("packs @drift/mcp with only dist files and a compiled drift-mcp bin", async () => {
    const packed = await packWorkspacePackage("packages/mcp");

    await expectSourcePrepack("packages/mcp");
    expect(packed.manifest.name).toBe("@drift/mcp");
    expectPackageMetadata(packed.manifest);
    expect(packed.manifest.bin?.["drift-mcp"]).toBe("./dist/bin.js");
    expect(packed.manifest.exports?.["."]?.import).toBe("./dist/index.js");
    expect(packed.files).toContain("dist/bin.js");
    expect(packed.files).toContain("dist/index.d.ts");
    expect(packed.files).toContain("README.md");
    expectDistOnly(packed.files);
    expectNoWorkspaceDependencies(packed.manifest);
  }, 30000);

  it("packs all workspace packages with local tarballs available for the installed-flow smoke", async () => {
    const packed = await packAllWorkspacePackages();

    expect(Object.keys(packed).sort()).toEqual([
      "@drift/cli",
      "@drift/core",
      "@drift/mcp",
      "@drift/storage"
    ]);
    expect(Object.values(packed).every((entry) => entry.tarballPath.endsWith(".tgz"))).toBe(true);
  }, 30000);
});
