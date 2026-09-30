import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Codex } from "../../plugins/codex-security/mcp-app/node_modules/@openai/codex-sdk/dist/index.js";
import {
  createIsolatedHome,
  importAmbientAuth,
  resolveCodexCommand,
} from "../../sdk/typescript/dist/runtime.js";
import { codexSettings, prepareEval, runPreparedEval } from "./harness.mjs";

const reports = fileURLToPath(new URL("./reports/", import.meta.url));
await mkdir(reports, { recursive: true });
const reportDirectory = await mkdtemp(join(reports, "run-"));
const root = await mkdtemp(join(tmpdir(), "source-audit-"));
const home = await createIsolatedHome();
console.log(`Eval artifacts: ${reportDirectory}`);
try {
  await importAmbientAuth(
    process.env.CODEX_HOME || join(homedir(), ".codex"),
    home,
  );
  const prepared = await prepareEval(root);
  const codexPath = await realpath(resolveCodexCommand({}).command);
  const codex = new Codex(codexSettings(home, codexPath));
  const { report, semanticResult } = await runPreparedEval(prepared, codex, {
    model: process.argv[2],
  });
  await writeFile(
    join(reportDirectory, "result.json"),
    JSON.stringify(semanticResult, null, 2) + "\n",
  );
  await writeFile(
    join(reportDirectory, "report.json"),
    JSON.stringify(report, null, 2) + "\n",
  );
  console.log(JSON.stringify(report, null, 2));
  process.exitCode = report.passed ? 0 : 1;
} finally {
  await rm(root, { recursive: true, force: true });
  await rm(home, { recursive: true, force: true });
}
