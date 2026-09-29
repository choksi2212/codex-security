import { brotliCompressSync, brotliDecompressSync } from "node:zlib";
import { describe, expect, test } from "bun:test";

const { assertPublicPackageContents } = (await import(
  new URL("../scripts/package-internal-references.mjs", import.meta.url).href
)) as {
  assertPublicPackageContents: (
    archiveBytes: Buffer,
    archiveFiles: Map<string, Buffer>,
  ) => void;
};

function inspect(entries: [string, Buffer][], metadata = "") {
  const chunks = entries.flatMap(([path, contents]) => [
    Buffer.from(`${path}\0${metadata}\0`),
    contents,
  ]);
  const archive = Buffer.concat(chunks);
  const files = new Map<string, Buffer>();
  let offset = 0;
  for (const [index, [path, contents]] of entries.entries()) {
    offset += chunks[index * 2]!.length;
    files.set(path, archive.subarray(offset, offset + contents.length));
    offset += contents.length;
  }
  assertPublicPackageContents(archive, files);
}

// Valid compressed bytes contain a marker-like sequence absent from the text.
const compressedFixture = Buffer.from(
  "G58AAGRgnikP5mWEcAF4L/70rY0DMLgq+du/Il7KM3pABrBwrD1HTy9f2iPXD9nLS+eeyfBS9jDPuLehk60dpTuQ79FQP7p/aAf/wTf6JztZL0zOmf5MxsTNWvJn24c4O36Wn683/mQze6hJHFvvx3oTW0UrVZo7fnHstXN8INaut32GZmyr3snPxr3yZ7ggGbghAw==",
  "base64",
);

function split(contents: Buffer): [string, Buffer][] {
  const midpoint = Math.floor(contents.length / 2);
  return [
    ["package/runtime.br.part-001", contents.subarray(midpoint)],
    ["package/runtime.br.part-000", contents.subarray(0, midpoint)],
  ];
}

describe("npm package internal references", () => {
  test("accepts marker-like compressed bytes in standalone and split Brotli", () => {
    expect(compressedFixture.toString("utf8")).toContain("=GO/_");
    expect(
      brotliDecompressSync(compressedFixture).toString("utf8"),
    ).not.toContain("/");
    expect(() =>
      inspect([["package/runtime.br", compressedFixture]]),
    ).not.toThrow();
    expect(() => inspect(split(compressedFixture))).not.toThrow();
  });

  test("rejects references in decoded standalone and split Brotli", () => {
    const compressed = brotliCompressSync(Buffer.from("go/example"));
    for (const entries of [
      [["package/runtime.br", compressed]] as [string, Buffer][],
      split(compressed),
    ]) {
      expect(() => inspect(entries)).toThrow("internal reference");
    }
  });

  test("keeps scanning uncompressed source, native bytes, paths, and tar metadata", () => {
    for (const path of ["package/index.js", "package/native/runtime.node"]) {
      expect(() => inspect([[path, Buffer.from("go/example")]])).toThrow(
        "internal reference",
      );
    }
    expect(() =>
      inspect([["package/go/example.br", compressedFixture]]),
    ).toThrow("internal reference");
    expect(() =>
      inspect([["package/runtime.br", compressedFixture]], "go/example"),
    ).toThrow("internal reference");
  });

  test("rejects malformed and trailing Brotli in standalone and split members", () => {
    const trailing = Buffer.concat([compressedFixture, Buffer.from("tail")]);
    for (const bytes of [compressedFixture.subarray(0, -1), trailing]) {
      expect(() => inspect([["package/runtime.br", bytes]])).toThrow();
      expect(() => inspect(split(bytes))).toThrow();
    }
  });
});
