import { win32 } from "node:path";
import type { WindowsBinding, WindowsHandle } from "./windows-binding.mjs";
import { windowsFlags as flags } from "./windows-flags.mjs";

export const widePath = (path: string): Buffer => Buffer.from(path, "utf16le");
export const pathText = (path: Buffer): string => path.toString("utf16le");

export function windowsParts(value: string): [string, string, string] {
  const path = value.replaceAll("/", "\\");
  if (path.startsWith("\\\\")) {
    const start = path.slice(0, 8).toUpperCase() === "\\\\?\\UNC\\" ? 8 : 2;
    const server = path.indexOf("\\", start);
    const share = server === -1 ? -1 : path.indexOf("\\", server + 1);
    return share === -1
      ? [value, "", ""]
      : [value.slice(0, share), value[share]!, value.slice(share + 1)];
  }
  const drive = path[1] === ":" ? 2 : 0;
  const root = path[drive] === "\\" ? 1 : 0;
  return [
    value.slice(0, drive),
    value.slice(drive, drive + root),
    value.slice(drive + root),
  ];
}

export function windowsJoin(left: string, right: string): string {
  const [leftDrive, leftRoot, leftPath] = windowsParts(left);
  const [rightDrive, rightRoot, rightPath] = windowsParts(right);
  if (rightRoot) return (rightDrive || leftDrive) + rightRoot + rightPath;
  if (rightDrive && rightDrive.toLowerCase() !== leftDrive.toLowerCase())
    return right;
  const drive = rightDrive || leftDrive;
  const path =
    leftPath + (leftPath && !/[/\\]$/u.test(leftPath) ? "\\" : "") + rightPath;
  const root =
    leftRoot || (path && drive && !/[:/\\]$/u.test(drive) ? "\\" : "");
  return drive + root + path;
}

export function windowsFileSystem(native: WindowsBinding) {
  function check(error: number, path: Buffer): void {
    if (error === 0) return;
    const code = new Map([
      [2, "ENOENT"],
      [3, "ENOENT"],
      [267, "ENOTDIR"],
      [1921, "ELOOP"],
    ]).get(error);
    throw Object.assign(
      new Error(`Windows filesystem error ${error}: ${pathText(path)}`),
      { code, winerror: error },
    );
  }

  function absolute(path: Buffer): Buffer {
    const result = native.windowsAbsolutePath(path);
    check(result.error, path);
    return result.value;
  }

  function operationPath(path: Buffer): Buffer {
    const resolved = absolute(path);
    const text = pathText(resolved);
    if (text.startsWith("\\\\?\\") || text.startsWith("\\\\.\\"))
      return resolved;
    return widePath(
      text.startsWith("\\\\")
        ? `\\\\?\\UNC\\${text.slice(2)}`
        : `\\\\?\\${text}`,
    );
  }

  function withFile<T>(
    path: Buffer,
    access: number,
    action: (handle: WindowsHandle) => T,
    disposition: number = flags.OPEN_EXISTING,
    follow = true,
  ): T {
    const result = native.openWindowsFile(
      operationPath(path),
      access,
      flags.FILE_SHARE_READ | flags.FILE_SHARE_WRITE | flags.FILE_SHARE_DELETE,
      disposition,
      (access === flags.GENERIC_READ ? 0 : flags.FILE_FLAG_BACKUP_SEMANTICS) |
        (follow ? 0 : flags.FILE_FLAG_OPEN_REPARSE_POINT),
    );
    check(result.error, path);
    const handle = result.handle!;
    try {
      return action(handle);
    } finally {
      check(handle.close(), path);
    }
  }

  function finalPath(text: string): string {
    const path = widePath(text);
    return withFile(path, 0, (handle) => {
      const result = handle.finalPath(0);
      check(result.error, path);
      return pathText(result.path);
    });
  }

  function readlink(path: Buffer): Buffer {
    const result = native.windowsReadLink(operationPath(path));
    check(result.error, path);
    return result.value;
  }

  function realpath(path: Buffer, strict = true): Buffer {
    function normalize(value: string): string {
      const verbatim = value.startsWith("\\\\?\\");
      const text = verbatim
        ? value.replaceAll("/", "\\")
        : pathText(absolute(widePath(value)));
      // Verbatim paths bypass Win32 dot parsing; normalize only below their root.
      const root =
        (verbatim
          ? /^\\\\\?\\(?:UNC\\[^\\]+\\[^\\]+(?:\\|$)|[^\\]+\\)/iu.exec(
              text,
            )?.[0]
          : undefined) ?? win32.parse(text).root;
      const tail = text.slice(root.length);
      return (
        root +
        (verbatim ? win32.join("\\", tail).slice(1) : tail).replace(/\\+$/u, "")
      );
    }
    let text = pathText(path);
    if (win32.normalize(text).toLowerCase() === "nul")
      return widePath("\\\\.\\NUL");
    if (!win32.isAbsolute(text))
      text = windowsJoin(pathText(absolute(widePath("."))), text);
    const normalized = normalize(text);
    text = pathText(absolute(widePath(normalized)));
    const seen = new Set<string>();
    let initialError: number | undefined;
    const tail: string[] = [];
    while (true) {
      try {
        text = finalPath(text);
        break;
      } catch (error) {
        if (strict) throw error;
        const winerror = (error as { winerror?: number }).winerror;
        // Match pathlib's non-strict Windows resolution errors.
        if (
          ![
            1, 2, 3, 5, 21, 32, 50, 53, 65, 67, 87, 123, 161, 1920, 1921,
          ].includes(winerror ?? 0)
        )
          throw error;
        initialError ??= winerror;
        const value = widePath(text);
        // Unicode lowercasing can merge distinct Windows filenames.
        if (winerror === 1921 || seen.has(text)) check(1921, value);
        seen.add(text);
        const parent = win32.dirname(text);
        if (parent === text) break;
        let target: Buffer | undefined;
        try {
          target = readlink(value);
        } catch {
          // Missing and ordinary entries have no link target to follow.
        }
        if (target !== undefined) {
          // Native link targets retain literal trailing dots and spaces.
          text = normalize(
            win32.toNamespacedPath(windowsJoin(parent, pathText(target))),
          );
          continue;
        }
        tail.push(win32.basename(text));
        text = parent;
      }
    }
    // These are filename components; a:stream must not become drive A.
    if (tail.length)
      text = `${text.replace(/\\$/u, "")}\\${tail.reverse().join("\\")}`;
    if (normalized.startsWith("\\\\?\\")) return widePath(text);
    const shortened = text.startsWith("\\\\?\\UNC\\")
      ? `\\\\${text.slice(8)}`
      : text.startsWith("\\\\?\\")
        ? text.slice(4)
        : text;
    // Like pathlib, remove the device prefix only if that spelling resolves too.
    try {
      if (finalPath(shortened) === text) text = shortened;
    } catch (error) {
      // Extended paths can be valid when their ordinary spelling is not.
      if (
        !strict &&
        (error as { winerror?: number }).winerror === initialError &&
        pathText(operationPath(widePath(shortened))) === text
      )
        text = shortened;
    }
    return widePath(text);
  }

  function stat(path: Buffer, follow = true) {
    return withFile(
      path,
      flags.FILE_READ_ATTRIBUTES,
      (handle) => {
        const info = handle.attributes();
        check(info.error, path);
        const type = handle.fileType();
        check(type.error, path);
        const link = !follow && info.reparseTag === 0xa000000c;
        const directory =
          (info.attributes & flags.FILE_ATTRIBUTE_DIRECTORY) !== 0;
        return {
          isDirectory: () => !link && directory,
          isFile: () => !link && !directory && type.value === 1,
          isSymbolicLink: () => link,
          isReparsePoint: () =>
            (info.attributes & flags.FILE_ATTRIBUTE_REPARSE_POINT) !== 0,
        };
      },
      flags.OPEN_EXISTING,
      follow,
    );
  }

  function identity(path: Buffer) {
    return withFile(path, flags.FILE_READ_ATTRIBUTES, (handle) => {
      const result = handle.identity();
      check(result.error, path);
      return { volume: result.volume, fileId: result.fileId };
    });
  }

  function entriesWithTypes(path: Buffer) {
    const result = native.windowsDirectoryEntries(operationPath(path));
    check(result.error, path);
    return result.value.map(({ name, isDirectory, isSymbolicLink }) => ({
      name,
      isDirectory: () => isDirectory,
      isSymbolicLink: () => isSymbolicLink,
    }));
  }

  function mkdir(path: Buffer): void {
    check(native.createWindowsDirectories(operationPath(path)), path);
  }

  function readInto(path: Buffer, buffer: Buffer): number {
    return withFile(path, flags.GENERIC_READ, (handle) => {
      let length = 0;
      while (length < buffer.length) {
        const result = handle.read(
          buffer,
          length,
          Math.min(buffer.length - length, 0xffffffff),
        );
        check(result.error, path);
        if (result.value === 0) break;
        length += result.value;
      }
      return length;
    });
  }

  function readFile(path: Buffer): Buffer {
    return withFile(path, flags.GENERIC_READ, (handle) => {
      const chunks: Buffer[] = [];
      while (true) {
        const chunk = Buffer.alloc(64 * 1024);
        const result = handle.read(chunk, 0, chunk.length);
        check(result.error, path);
        if (result.value === 0) return Buffer.concat(chunks);
        chunks.push(chunk.subarray(0, result.value));
      }
    });
  }

  function writeFile(
    path: Buffer,
    data: Buffer | Iterable<Buffer>,
    exclusive = false,
  ): void {
    withFile(
      path,
      flags.GENERIC_WRITE,
      (handle) => {
        for (const buffer of Buffer.isBuffer(data) ? [data] : data) {
          let offset = 0;
          while (offset < buffer.length) {
            const result = handle.write(
              buffer,
              offset,
              Math.min(buffer.length - offset, 0xffffffff),
            );
            check(result.error, path);
            if (result.value === 0)
              throw new Error(
                `Windows file write made no progress: ${pathText(path)}`,
              );
            offset += result.value;
          }
        }
      },
      exclusive ? flags.CREATE_NEW : flags.CREATE_ALWAYS,
    );
  }

  function rename(source: Buffer, destination: Buffer): void {
    withFile(
      source,
      flags.DELETE,
      (handle) => {
        check(handle.rename(operationPath(destination), true), destination);
      },
      flags.OPEN_EXISTING,
      false,
    );
  }

  function unlink(path: Buffer): void {
    withFile(
      path,
      flags.DELETE,
      (handle) => {
        check(handle.setDisposition(true), path);
      },
      flags.OPEN_EXISTING,
      false,
    );
  }

  return {
    absolute,
    realpath,
    stat,
    identity,
    entriesWithTypes,
    mkdir,
    readlink,
    readInto,
    readFile,
    writeFile,
    rename,
    unlink,
  };
}
