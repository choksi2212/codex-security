import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "../../sdk/typescript/node_modules/esbuild/lib/main.js";

// Reuse the native preflight and warning handling exercised by Deep Scan.
const bundle = await build({
  entryPoints: [
    fileURLToPath(
      new URL(
        "../../plugins/codex-security/mcp-app/src/deep-scan/permission-profile-preflight.ts",
        import.meta.url,
      ),
    ),
  ],
  bundle: true,
  format: "esm",
  platform: "node",
  write: false,
});
export const {
  preflightDeepScanWorkerPermissionProfile,
  deepScanPermissionProfileFallbackError,
} = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);

/** Keep temporary source and authentication alive until cancelled work stops. */
export async function withEvalState(createHome, run) {
  const controller = new AbortController();
  let interrupted;
  const handlers = ["SIGINT", "SIGTERM"].map((signal) => {
    const handler = () => {
      interrupted = signal;
      process.exitCode = signal === "SIGINT" ? 130 : 143;
      controller.abort(
        new DOMException(`Eval interrupted by ${signal}`, "AbortError"),
      );
    };
    process.on(signal, handler);
    return [signal, handler];
  });
  let root;
  let home;
  try {
    root = await mkdtemp(join(tmpdir(), "source-audit-"));
    home = await createHome();
    controller.signal.throwIfAborted();
    const result = await run({ root, home, signal: controller.signal });
    controller.signal.throwIfAborted();
    return result;
  } catch (error) {
    if (!interrupted) throw error;
    process.exitCode = interrupted === "SIGINT" ? 130 : 143;
  } finally {
    try {
      await Promise.all(
        [root, home]
          .filter(Boolean)
          .map((path) => rm(path, { recursive: true, force: true })),
      );
    } finally {
      for (const [signal, handler] of handlers) process.off(signal, handler);
    }
  }
}
