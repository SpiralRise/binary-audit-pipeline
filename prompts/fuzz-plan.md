# Fuzz target selection prompt

You are helping me turn the output of a binary static-audit pipeline into a
fuzzing plan.

Input directories:

- Target directory: `<TARGET_DIR>`
- Pipeline output directory: `<OUT_DIR>`

## Step 0: coverage check

Inspect the target directory structure. If it contains `.zip`, `.tar`, `.gz`,
`.7z`, `.img`, `.bin` or other files that look like archives or firmware
images, list them and tell me they must be extracted with `binwalk` or a
similar tool before analysis. Do not pretend these files were covered.

## Step 1: read the pipeline output

Read, in this order:

- `02_capa/summary.md` and `02_capa/hits.json`
- `03_cwe/summary.md` and `03_cwe/findings.json`
- `05_semgrep/semgrep.json`
- `06_joern/taint_flows.txt`
- `07_script/` (if present)
- `高风险点清单.md`

## Step 2: rank candidates

For each candidate function, report:

1. file and function name;
2. why it is a candidate (network input, file parser, length field,
   `memcpy`/`strcpy`, protocol handler, command execution, etc.);
3. which tool or flow supports the claim;
4. suggested harness type (AFL++ persistent mode, libFuzzer, standalone);
5. required input format and seed corpus;
6. priority (P0/P1/P2) and the reason.

Rank the top 10 candidates.

## Step 3: separate evidence levels

Clearly separate:

- **Confirmed flow**: a source-to-sink flow exists in `06_joern/taint_flows.txt`.
- **Sink hit only**: the dangerous function appears in the sink table or
  pseudocode, but no complete flow was found.
- **Uncovered**: files or functions that Joern/Ghidra did not analyze.

Do not invent vulnerabilities. If the output does not prove reachability, say
so explicitly.

## Step 4: final list

At the end, list:

- the top 10 fuzz targets in priority order;
- archives or firmware images that still need extraction;
- files/functions not covered by Joern or Ghidra;
- assumptions you made.

Prefer concise, evidence-based reasoning over generic advice.
