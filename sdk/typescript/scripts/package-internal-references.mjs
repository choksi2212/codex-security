import { brotliDecompressSync } from "node:zlib";

export const MAX_EXPANDED_ASSET_BYTES = 32 * 1024 * 1024;

const internalMarker =
  /(?:internal\.api\.openai\.org|gateway\.[a-z0-9.-]*internal|\.openai\.org|openai\.firewall\.socket\.dev|socket\x2dfirewall\x2dregistry|openai\.(?:enterprise\.)?slack\.com|app\.slack\.com\/client|(?:app\.notion\.com\/p|notion\.so)\/openai|linear\.app\/openai|(?:github\.com[:/]|api\.github\.com\/repos\/|raw\.githubusercontent\.com\/)openai\/openai(?:\.git)?(?:[^a-z0-9_-]|$)|LicenseRef\x2dProprietary|\/Users\/|\/home\/dev-user|flow\.apps\.openai\.org|(?:^|[^a-z0-9_-])go\/[a-z0-9_-]+)/iu;

export function assertPublicPackageContents(archiveBytes, archiveFiles) {
  const uncompressed = Buffer.from(archiveBytes);
  const payloads = [uncompressed];
  const compressedParts = new Map();

  function brotliPayload(bytes, file) {
    const result = brotliDecompressSync(bytes, {
      info: true,
      maxOutputLength: MAX_EXPANDED_ASSET_BYTES,
    });
    if (result.engine.bytesWritten !== bytes.length) {
      throw new Error(`npm tarball contains trailing Brotli data: ${file}.`);
    }
    return result.buffer;
  }

  for (const [file, bytes] of archiveFiles) {
    const match = /^(.*\.br)\.part-([0-9]+)$/iu.exec(file);
    if (match !== null) {
      const [, name, part] = match;
      const parts = compressedParts.get(name) ?? [];
      parts.push({ file, part: Number(part), bytes });
      compressedParts.set(name, parts);
    } else if (/\.br$/iu.test(file)) {
      payloads.push(brotliPayload(bytes, file));
    } else {
      continue;
    }
    // Scan compressed members after decoding; retain tar headers and other bytes.
    const start = bytes.byteOffset - archiveBytes.byteOffset;
    uncompressed.fill(0, start, start + bytes.length);
  }
  for (const parts of compressedParts.values()) {
    parts.sort((left, right) => left.part - right.part);
    const bytes = Buffer.concat(parts.map((part) => part.bytes));
    payloads.push(brotliPayload(bytes, parts[0].file));
  }
  for (const contents of payloads) {
    if (internalMarker.test(contents.toString("utf8"))) {
      throw new Error("npm tarball contains an internal reference.");
    }
  }
}
