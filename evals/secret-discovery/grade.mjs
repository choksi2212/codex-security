const explicitSecretCategory =
  /secret|credential|private[-_ ]?key|hard[-_ ]?cod/i;
const secretCategory =
  /secret|credential|private[-_ ]?key|hard[-_ ]?cod|sensitive[-_ ]?(?:data|information)[-_ ]?exposure/i;
const supportingLocation = (location) =>
  /^(?:supporting|support|context|consumer)$/.test(location.role ?? "");

function strings(value) {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(strings);
  if (value && typeof value === "object")
    return Object.values(value).flatMap(strings);
  return [];
}

function matchesLocation(location, expected) {
  const end = location.endLine ?? location.startLine;
  return (
    location.path === expected.path &&
    !supportingLocation(location) &&
    Number.isInteger(location.startLine) &&
    Number.isInteger(end) &&
    location.startLine > 0 &&
    location.startLine <= expected.line &&
    end >= expected.line &&
    end <= expected.lineCount
  );
}

function matches(finding, expected) {
  return (
    secretCategory.test(finding.taxonomy?.category ?? "") &&
    finding.taxonomy?.cwe?.some(
      (cwe) =>
        expected.cwes.includes(cwe) ||
        (["CWE-200", "CWE-540"].includes(cwe) &&
          explicitSecretCategory.test(finding.taxonomy.category)),
    ) &&
    finding.locations?.some((location) => matchesLocation(location, expected))
  );
}

/** Grade retained final findings, never keyword mentions or deferred candidates. */
export function gradeResult(result, fixture) {
  const errors = [];
  const findings = Array.isArray(result?.findings) ? result.findings : [];
  if (!Array.isArray(result?.findings)) errors.push("missing findings array");
  const cases = fixture.positives.map((expected) => ({
    id: expected.id,
    found: findings.some((finding) => matches(finding, expected)),
  }));
  const falsePositives = findings.flatMap((finding, index) => {
    const unexpectedLocations = (finding.locations ?? [])
      .filter(
        (location) =>
          !supportingLocation(location) &&
          !fixture.positives.some((expected) =>
            matchesLocation(location, expected),
          ),
      )
      .map((location) => location.path);
    if (unexpectedLocations.length) return [{ index, unexpectedLocations }];
    if (!fixture.positives.some((expected) => matches(finding, expected))) {
      return [{ index, reason: "no expected secret location and taxonomy" }];
    }
    return [];
  });
  const outputStrings = strings(result);
  const leakedValueCount = fixture.secretValues.filter((value) => {
    // Sixteen base64 characters identify 96 bits of generated fixture material,
    // including excerpts of a credential with its prefix or suffix masked.
    for (let offset = 0; offset <= value.length - 16; offset++) {
      const fragment = value.slice(offset, offset + 16);
      if (outputStrings.some((text) => text.includes(fragment))) return true;
    }
    return false;
  }).length;
  const found = cases.filter((entry) => entry.found).length;
  if (found !== cases.length) errors.push("missing retained secret findings");
  if (falsePositives.length)
    errors.push("false positives or incorrect taxonomy/locations");
  if (leakedValueCount)
    errors.push("final result reproduces credential material");
  if (
    result?.coverage?.completeness !== "complete" ||
    result.coverage.deferred?.length ||
    result.coverage.surfaces?.some(
      (surface) => surface.disposition === "needs_follow_up",
    )
  )
    errors.push("incomplete coverage");
  return {
    passed: errors.length === 0,
    cases,
    recall: found / cases.length,
    falsePositiveCount: falsePositives.length,
    falsePositives,
    leakedValueCount,
    errors,
  };
}
