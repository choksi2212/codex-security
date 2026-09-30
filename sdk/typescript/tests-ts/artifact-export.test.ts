import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { exportArtifact } from "../src/index.js";

describe("offline artifact export", () => {
  test("exports canonical policy Markdown before completion without its convenience file", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-offline-model-"));
    const source = join(root, "policy");
    const output = join(root, "threatmodel.md");
    const content =
      "# Component model\n\n| Asset | Boundary |\n| --- | --- |\n| Café | Caller → service |\n\n```text\nline one\n  line two\n```\n";
    const manifest = {
      documentType: "codex-security.policy-draft",
      schemaVersion: "1.0",
      repository: "/synthetic/repository",
      scope: "services/api",
      revision: "synthetic-revision",
      status: "threat_model_ready",
      threatModel: {
        format: "markdown",
        content,
        scope: { includePaths: ["services/api"], excludePaths: [] },
        origin: "generated",
      },
    };
    await mkdir(source);
    const original = JSON.stringify(manifest);
    await writeFile(join(source, "policy-draft.json"), original);
    try {
      const result = await exportArtifact({
        source: { directory: source },
        artifact: "threat-model",
        output,
      });
      expect(result.path).toBe(output);
      expect(result.provenance).toMatchObject({
        status: "threat_model_ready",
        provisional: true,
      });
      const exported = await readFile(output, "utf8");
      expect(exported).toStartWith(content);
      expect(exported).toContain("services/api");
      expect(await readFile(join(source, "policy-draft.json"), "utf8")).toBe(
        original,
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("exports historical Markdown and rejects missing models or overwriting source artifacts", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-legacy-model-"));
    const source = join(root, "policy");
    await mkdir(source);
    try {
      await expect(
        exportArtifact({
          source: { directory: source },
          artifact: "threat-model",
          output: join(root, "missing.md"),
        }),
      ).rejects.toThrow("No saved threat model");
      const original = "# Historical model\n\nSource-backed details.\n";
      await writeFile(join(source, "THREAT_MODEL.md"), original);
      await exportArtifact({
        source: { directory: source },
        artifact: "threat-model",
        output: join(root, "threatmodel.md"),
      });
      expect(await readFile(join(root, "threatmodel.md"), "utf8")).toBe(
        original,
      );
      await expect(
        exportArtifact({
          source: { directory: source },
          artifact: "threat-model",
          output: join(source, "THREAT_MODEL.md"),
        }),
      ).rejects.toThrow("cannot overwrite a scan artifact");
      expect(await readFile(join(source, "THREAT_MODEL.md"), "utf8")).toBe(
        original,
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
