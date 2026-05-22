import type { FactRecord,FileSnapshot } from "@drift/core";
import { extractFactsFromFile,factRecord,fileSnapshotForFile } from "./fact-extraction.js";
import { runRustEngine } from "./rust-engine.js";
import { walkIndexableFiles } from "./ts-fallback-scanner.js";

export interface ScanData {
  files: string[];
  facts: FactRecord[];
  snapshots: FileSnapshot[];
  engineSource: "rust" | "typescript";
}

export interface RustEngineScanOutput {
  engine_version: string;
  files: Array<{
    file_path: string;
    content_hash: string;
    byte_size: number;
  }>;
  facts: Array<{
    kind: FactRecord["kind"];
    file_path: string;
    name: string;
    value?: string;
    start_line: number;
    end_line: number;
  }>;
}

export function collectScanData(input: {
  repoId: string;
  scanId: string;
  repoRoot: string;
}): ScanData {
  const rust = collectScanDataFromRust(input);
  if (rust) {
    return rust;
  }

  const files = walkIndexableFiles(input.repoRoot);
  return {
    files,
    facts: files.flatMap((filePath) =>
      extractFactsFromFile({
        repoId: input.repoId,
        scanId: input.scanId,
        repoRoot: input.repoRoot,
        filePath
      })
    ),
    snapshots: files.map((filePath) =>
      fileSnapshotForFile({
        repoId: input.repoId,
        scanId: input.scanId,
        repoRoot: input.repoRoot,
        filePath
      })
    ),
    engineSource: "typescript"
  };
}

export function collectScanDataFromRust(input: {
  repoId: string;
  scanId: string;
  repoRoot: string;
}): ScanData | undefined {
  const output = runRustEngine(["scan-repo", input.repoRoot]);
  if (!output) {
    return undefined;
  }
  const parsed = JSON.parse(output) as RustEngineScanOutput;
  return {
    files: parsed.files.map((file) => file.file_path).sort(),
    facts: parsed.facts.map((fact) =>
      factRecord(
        { repoId: input.repoId, scanId: input.scanId, filePath: fact.file_path },
        fact.kind,
        fact.name,
        fact.value ?? undefined,
        fact.start_line,
        fact.end_line
      )
    ),
    snapshots: parsed.files.map((file) => ({
      repo_id: input.repoId,
      scan_id: input.scanId,
      file_path: file.file_path,
      content_hash: file.content_hash,
      byte_size: file.byte_size,
      indexed: true
    })),
    engineSource: "rust"
  };
}
