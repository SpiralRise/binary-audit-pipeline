---
name: binary-audit-triage
description: Turn a binary-audit-pipeline output directory into a ranked fuzz-target plan. Use when the user has run binary-audit-pipeline (or has capa / cwe_checker / Semgrep / Joern results for stripped binaries) and asks what to fuzz next, how to write a harness, or which findings actually matter.
---

# Binary audit triage

You are helping the user turn the output of a binary static-audit pipeline into
a concrete fuzzing plan.

Inputs:

- target directory: `<TARGET_DIR>` (the binaries that were scanned)
- pipeline output directory: `<OUT_DIR>` (contains `01_cve/` ... `07_script/`
  and `高风险点清单.md`)

If either path is unknown, ask for it before doing anything else.

## Step 0: coverage check

Inspect `<TARGET_DIR>`. If it contains `.zip`, `.tar`, `.gz`, `.7z`, `.img`,
`.bin` or anything that looks like an archive or firmware image, list them and
state that they must be extracted (`binwalk`, `unsquashfs`, ...) before they can
be analyzed. Never claim these were covered.

Also report what the pipeline skipped: packed binaries, files over the size
limit, and anything Ghidra or Joern did not process.

## Step 1: read the output

Read in this order:

1. `高风险点清单.md` — the aggregated report; use it for the overview.
2. `02_capa/summary.md`, `02_capa/hits.json` — capabilities per file.
3. `03_cwe/summary.md`, `03_cwe/findings.json` — real defects versus CWE676 hints.
4. `05_semgrep/semgrep.json` — dangerous calls in decompiled code.
5. `06_joern/taint_flows.txt` — source-to-sink flows, plus the sink table at the end.
6. `07_script/` — findings in bundled shell / Python / JS scripts, if present.
7. `01_cve/cve.json` — only if step 1 was enabled.

## Step 2: rank candidates

For each candidate function report:

1. file and function name (keep the decompiled `FUN_xxxx` name if symbols are stripped);
2. why it is a candidate: network input, file parser, length field, `memcpy` /
   `strcpy`, protocol handler, command execution, TLS handshake, etc.;
3. which tool or flow supports the claim;
4. suggested harness: AFL++ persistent mode, libFuzzer, or standalone driver;
5. required input format and a seed corpus suggestion;
6. priority P0 / P1 / P2 with a one-line reason.

Return the top 10, ordered.

## Step 3: separate evidence levels

Never blur these three:

- **confirmed flow** — a source-to-sink path exists in `06_joern/taint_flows.txt`;
- **sink hit only** — a dangerous call exists but reachability is unproven;
- **uncovered** — files or functions no tool analyzed.

Do not invent vulnerabilities. If the output does not prove reachability, say so
in one sentence and move on.

## Step 4: final summary

End with:

- the top 10 targets in priority order;
- archives or firmware images that still need extraction;
- files and functions not covered by Ghidra or Joern;
- assumptions you made, and what would falsify them.

Prefer concise, evidence-based reasoning. Quote file and function names, not
generic advice.
