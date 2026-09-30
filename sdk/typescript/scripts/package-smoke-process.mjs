import { spawnSync } from "node:child_process";
import { stat } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { packageSmokeTimeouts } from "./package-smoke-timeouts.mjs";

const { commandTimeoutMs: PACKAGE_SMOKE_TIMEOUT_MS } = packageSmokeTimeouts();

export function runPackageCommand(
  command,
  args,
  {
    cwd,
    env,
    capture = false,
    input,
    windowsVerbatimArguments = false,
    timeout = PACKAGE_SMOKE_TIMEOUT_MS,
  } = {},
) {
  const result = spawnSync(command, args, {
    cwd,
    env,
    encoding: "utf8",
    input,
    stdio: capture ? "pipe" : "inherit",
    timeout,
    killSignal: "SIGKILL",
    windowsVerbatimArguments,
    windowsHide: true,
  });

  if (result.error?.code === "ETIMEDOUT") {
    throw new Error(
      `Package smoke command timed out after ${timeout} ms: ${command}.`,
      { cause: result.error },
    );
  }
  if (result.error !== undefined) {
    throw new Error(`Failed to run ${command}.`, { cause: result.error });
  }
  if (result.status !== 0) {
    const details = capture ? `\n${result.stderr.trim()}` : "";
    throw new Error(
      `${command} exited with status ${result.status}.${details}`,
    );
  }

  return result.stdout ?? "";
}

export async function resolveNpm() {
  const nodeDirectory = dirname(process.execPath);
  const candidates = [
    process.env.npm_execpath,
    resolve(nodeDirectory, "../lib/node_modules/npm/bin/npm-cli.js"),
    resolve(nodeDirectory, "node_modules/npm/bin/npm-cli.js"),
    resolve(nodeDirectory, "../node_modules/npm/bin/npm-cli.js"),
  ];

  for (const candidate of new Set(candidates)) {
    if (
      typeof candidate !== "string" ||
      basename(candidate).toLowerCase() !== "npm-cli.js"
    ) {
      continue;
    }

    try {
      if ((await stat(candidate)).isFile()) {
        return { command: process.execPath, args: [candidate] };
      }
    } catch (error) {
      if (error.code !== "ENOENT" && error.code !== "ENOTDIR") throw error;
    }
  }

  if (process.platform === "win32") {
    throw new Error("The Node.js installation does not include the npm CLI.");
  }

  return { command: "npm", args: [] };
}
