import { isUtf8 } from "node:buffer";

export function compareUnicode(left: string, right: string): number {
  let leftIndex = 0;
  let rightIndex = 0;
  while (leftIndex < left.length && rightIndex < right.length) {
    const leftPoint = left.codePointAt(leftIndex)!;
    const rightPoint = right.codePointAt(rightIndex)!;
    if (leftPoint !== rightPoint) return leftPoint - rightPoint;
    leftIndex += leftPoint > 0xffff ? 2 : 1;
    rightIndex += rightPoint > 0xffff ? 2 : 1;
  }
  return left.length - right.length;
}

export function decodeUtf8(bytes: Buffer): string {
  // Node 20's fatal TextDecoder can silently replace invalid input bytes.
  if (!isUtf8(bytes))
    throw new TypeError("The encoded data was not valid for encoding utf-8");
  return bytes.toString("utf8");
}
