# Current-source secret discovery eval

This small model eval runs the production `references/core-scan.md` workflow
against a generated repository. It measures discovery and final retention of
committed credential material without supplying finding hints, locations, or
expected labels to the model. Every value and key is generated locally, has no
external authority, and is never used to contact or authenticate to a service.

The six positive cases cover active source, an unused source constant,
integration-test source, a hidden environment file containing a database URL,
JSON credentials, and an embedded private signing key. Negative controls cover
environment references, placeholders, a public key, public identifiers, and a
digest. The model must discover the positive cases from the source itself.

The final `findings` must retain every positive with an appropriate CWE,
credential-related category, and the actual source location.
Generic disclosure CWEs (`CWE-200`, `CWE-540`) also count when the category
explicitly identifies credential, secret, hardcoding, or private-key exposure.
Mentions in resolved questions, intermediate responses, or deferred coverage do
not count.
The grader also rejects unrelated non-supporting locations, incomplete coverage
(including deferred work or surfaces needing follow-up), and credential values
or fragments of at least 16 characters reproduced anywhere in the final semantic
result. Fixed private-key encoding headers do not count as secret material.
Finding counts alone cannot pass the eval. Explicitly labeled supporting
locations do not turn benign context into a false positive.

## Run

Use the repository's normal setup to install the MCP app dependencies and build
the TypeScript SDK. This eval reuses their pinned Codex SDK, CLI, and isolated
authentication-home helper; it adds no dependencies.

```sh
node evals/secret-discovery/run.mjs
```

An optional positional argument selects a model. When omitted, Codex selects its
default; the report marks that choice as unresolved because the SDK's turn
result does not expose the selected model. The run consumes model usage
and uses the caller's existing file-based Codex login or authentication
environment. It creates a temporary private Codex home, copies existing login
state with the SDK's authentication helper, and removes that home after the
run. Only runtime, proxy/certificate, and model-authentication environment
variables reach the Codex process; shell tools inherit Codex's core environment
with default credential exclusions. Login shells and shell snapshots are
disabled. It does not print authentication data or put it in the source fixture
or reports.

Source inspection is offline and read-only. A named, deny-by-default filesystem
profile allows only the generated repository, staged production references,
and minimal executable runtime paths; the harness, gold labels, reports, and
authentication home are not readable by model tools. The production prompt is
staged unchanged, with its SHA-256 recorded in the report. The caller supplies
zero subagents and a compact semantic-output schema; this measures the complete
core workflow's sequential fallback, not full SDK artifact publication or Deep
Scan scheduling. It does not inspect Git history or test live credential
validity.

The script prints aggregate grading and token usage, saves `report.json` and
`result.json` beneath ignored `reports/`, and exits nonzero when grading fails.
The source fixture and temporary model state are removed on exit. Reports may
contain generated fixture values when the non-disclosure check fails, but no
real service credentials are supplied to the model.

## Deterministic checks

```sh
node --test evals/secret-discovery/test_*.mjs
```

These Node-only checks run in CI. They verify source-only staging, exact
production-prompt loading, final-response grading, false-negative and
false-positive cases, path/line/CWE checks, credential-value disclosure checks,
and the restricted SDK configuration. The optional model run is not part of CI.
