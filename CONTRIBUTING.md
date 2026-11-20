# Contributing

Thanks for taking the time to look at this. The project is a small set of shell
and Python scripts wrapped in a Docker image; there is no framework to learn.

## Before you start

- **Bug fixes** and small improvements: open a PR directly.
- **Anything larger** (new tools, new steps, changed output format): open an
  issue first so we can agree on the shape before you write code.
- **Questions about usage**: use issues rather than email so the answer is
  searchable for the next person.

## Where things live

| Path | What it is |
| --- | --- |
| `audit.py` | host-side wrapper around `docker run` |
| `scripts/pipeline.sh` | runs the eight steps in order, handles resume |
| `scripts/*.py` | per-step parsers, scope selectors, summaries |
| `scripts/taint_scan.sc` | Joern taint query |
| `ghidra_scripts/` | Ghidra headless export |
| `rules/local/` | Semgrep rules for decompiled pseudocode |
| `prompts/`, `skills/` | AI handoff material (documentation only) |

Each step writes into its own `NN_*` directory under the output path, so most
changes are local to one file.

## Rules of the road

1. **Keep defaults stable.** New behaviour should sit behind an environment
   variable, in the same style as the existing `WITH_*`, `GHIDRA_SCOPE`,
   `RESUME` and `ONLY_STEP` switches. A PR that changes what a default run does
   needs a good reason.
2. **No new heavyweight dependencies without discussion.** The image is already
   several GB; adding a tool needs to be justified by what it catches.
3. **Fail loudly.** If a tool is missing or an input is malformed, print a clear
   error and exit non-zero instead of producing a half-empty report.
4. **Keep the report honest.** Any new finding type must say what it proves and
   what it does not. The existing report separates confirmed defects from hints
   such as CWE676; follow that pattern.

## Testing a change

A full run takes about 24 minutes on a 4-core / 16 GB machine (see the case
study). While developing, use a small directory and a single step:

```bash
python3 audit.py ./samples ./out-test --only 2
```

Then re-run the summary step only:

```bash
python3 audit.py ./samples ./out-test --only 8
```

In a PR description, include the command you ran, the machine specs, and the
before/after output if the change affects the report.

## Third-party code

`cwe_pcode/` is patched third-party code (LGPL-3.0) and `rules/thirdparty/`
contains community Semgrep rules. Changes there must keep the upstream license
headers intact and be noted in `THIRD_PARTY_LICENSES.md`.

## License

By contributing you agree that your contribution is licensed under the MIT
license used by this repository.

---

## 中文简述

- 修 bug 和小改动直接提 PR；新功能或改输出格式，先开 Issue 对齐方案。
- 新行为用环境变量开关控制，不要改变默认运行的结果。
- 提 PR 前用一个小目录跑一遍 `--only 2` 和 `--only 8`，并在 PR 里写清命令和机器配置。
- `cwe_pcode/` 是打了补丁的第三方代码（LGPL-3.0），改动时保留原有许可证头。
