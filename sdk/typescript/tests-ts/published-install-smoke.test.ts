import { afterEach, expect, test } from "bun:test";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const { verifyInstalledPackage } = (await import(
  new URL("../scripts/smoke-published-package.mjs", import.meta.url).href
)) as {
  verifyInstalledPackage: (
    consumer: string,
    environment: NodeJS.ProcessEnv,
  ) => Promise<void>;
};
const { runPackageCommand } = (await import(
  new URL("../scripts/package-smoke-process.mjs", import.meta.url).href
)) as {
  runPackageCommand: (
    command: string,
    args: string[],
    options: { capture: boolean; input?: string },
  ) => string;
};

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function installedFixture(cliVersion: string) {
  const consumer = await mkdtemp(join(tmpdir(), "published smoke "));
  directories.push(consumer);
  const installedRoot = join(
    consumer,
    "node_modules",
    "@openai",
    "codex-security",
  );
  const bin = join(consumer, "node_modules", ".bin");
  await mkdir(installedRoot, { recursive: true });
  await mkdir(bin);
  await writeFile(
    join(consumer, "package.json"),
    JSON.stringify({ type: "module" }),
  );
  await writeFile(
    join(installedRoot, "package.json"),
    JSON.stringify({
      name: "@openai/codex-security",
      version: "99.1.2",
      type: "module",
      exports: "./missing-public-entrypoint.js",
    }),
  );
  const shim = join(
    bin,
    process.platform === "win32" ? "codex-security.cmd" : "codex-security",
  );
  await writeFile(
    shim,
    process.platform === "win32"
      ? `@echo off\r\nif "%~1"=="--version" (echo ${cliVersion}) else (echo Usage: codex-security)\r\n`
      : `#!/bin/sh\nif [ "$1" = "--version" ]; then printf '%s\\n' '${cliVersion}'; else printf '%s\\n' 'Usage: codex-security'; fi\n`,
  );
  await chmod(shim, 0o755);
  return consumer;
}

test("fails when the installed CLI reports a different package version", async () => {
  const consumer = await installedFixture("99.1.1");
  await expect(verifyInstalledPackage(consumer, process.env)).rejects.toThrow(
    "99.1.2",
  );
});

test("uses the installed version and resolves the public SDK from the consumer", async () => {
  const consumer = await installedFixture("99.1.2");
  // The installed version need not match this checkout. Once CLI checks pass,
  // a missing published export must fail instead of loading the checkout's SDK.
  await expect(verifyInstalledPackage(consumer, process.env)).rejects.toThrow(
    "@openai/codex-security",
  );
});

test("package commands pass initialization input through stdin", () => {
  expect(
    runPackageCommand(
      process.execPath,
      ["-e", "process.stdin.pipe(process.stdout)"],
      {
        capture: true,
        input: '{"jsonrpc":"2.0","method":"initialize"}\n',
      },
    ),
  ).toBe('{"jsonrpc":"2.0","method":"initialize"}\n');
});

test("package commands propagate startup failures and diagnostics", () => {
  expect(() =>
    runPackageCommand(
      process.execPath,
      ["-e", 'console.error("synthetic startup failure"); process.exit(7)'],
      { capture: true },
    ),
  ).toThrow("exited with status 7.\nsynthetic startup failure");
});
