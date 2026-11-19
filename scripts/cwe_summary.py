#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""汇总 cwe_checker 结果：把「真正的 CWE 缺陷发现」与「CWE676 危险符号提示」分开。

用法: cwe_summary.py <out_dir>
输入: 03_cwe/<文件名>.txt（cwe_checker 的日志 + 末尾 JSON 数组）
输出:
  03_cwe/summary.md     人读汇总
  03_cwe/findings.json  机读汇总（缺陷条目全量，CWE676 只留计数）
stdout: 统计摘要（供 pipeline.sh tee 到 logs/03_cwe_summary.log）
"""
import json
import sys
from pathlib import Path

# CWE676 = “使用了危险函数”，几乎每个 ELF 都会报，只是提示，不算缺陷
HINT_ONLY = {"CWE676"}


def load_findings(text):
    """cwe_checker 把 JSON 数组打印在日志末尾，从后往前找顶格的 '[' 行。"""
    lines = text.splitlines()
    for i in range(len(lines) - 1, -1, -1):
        s = lines[i].strip()
        if s not in ("[", "[]"):
            continue
        try:
            data = json.loads("\n".join(lines[i:]))
        except Exception:
            continue
        if isinstance(data, list):
            return data
    return None


def hex_addr(value):
    try:
        return "0x%x" % int(str(value), 10)
    except Exception:
        return str(value)


def main():
    if len(sys.argv) < 2:
        print("usage: cwe_summary.py <out_dir>", file=sys.stderr)
        return 2
    out_dir = Path(sys.argv[1])
    cwe_dir = out_dir / "03_cwe"
    if not cwe_dir.is_dir():
        print("[!] 03_cwe 目录不存在: %s" % cwe_dir, file=sys.stderr)
        return 1

    files = []
    by_cwe = {}
    scanned = with_defects = hint_only = no_findings = unparsed = 0
    defect_total = hint_total = 0

    for path in sorted(cwe_dir.glob("*.txt")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        scanned += 1
        findings = load_findings(text)
        if findings is None:
            unparsed += 1
            continue

        defects, hints = [], 0
        for item in findings:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            if name in HINT_ONLY:
                hints += 1
                continue
            defects.append({
                "name": name,
                "addresses": [hex_addr(a) for a in (item.get("addresses") or [])],
                "description": str(item.get("description") or "").strip(),
                "symbols": item.get("symbols") or [],
            })

        item_cwe = {}
        for d in defects:
            item_cwe[d["name"]] = item_cwe.get(d["name"], 0) + 1
            by_cwe[d["name"]] = by_cwe.get(d["name"], 0) + 1
        defect_total += len(defects)
        hint_total += hints

        if defects:
            with_defects += 1
        elif hints:
            hint_only += 1
        else:
            no_findings += 1

        files.append({
            "file": path.name,
            "stem": path.stem,
            "defects": len(defects),
            "hints": hints,
            "cwe": item_cwe,
            "items": defects,
        })

    data = {
        "scanned": scanned,
        "with_defects": with_defects,
        "hint_only": hint_only,
        "no_findings": no_findings,
        "unparsed": unparsed,
        "defect_total": defect_total,
        "hint_total": hint_total,
        "by_cwe": by_cwe,
        "files": files,
    }
    (cwe_dir / "findings.json").write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    # ---- summary.md ----
    md = ["# cwe_checker 汇总（缺陷发现 / 危险符号提示 分开统计）", ""]
    md.append("- 扫描文件：%d 个" % scanned)
    md.append("- **有缺陷发现的文件：%d 个**（缺陷条目 %d 条）" % (with_defects, defect_total))
    md.append("- 仅有 CWE676 危险符号提示的文件：%d 个（提示 %d 条，不计入缺陷）"
              % (hint_only, hint_total))
    md.append("- 无任何发现的文件：%d 个" % no_findings)
    if unparsed:
        md.append("- JSON 解析失败的文件：%d 个（见原始 txt）" % unparsed)
    md.append("")
    if by_cwe:
        md.append("## 缺陷类型统计")
        md.append("")
        md.append("| CWE | 条数 |")
        md.append("| --- | --- |")
        for k, v in sorted(by_cwe.items(), key=lambda kv: (-kv[1], kv[0])):
            md.append("| %s | %d |" % (k, v))
        md.append("")

    md.append("## 文件总览")
    md.append("")
    md.append("| # | 文件 | 缺陷数 | 缺陷类型 | CWE676 提示数 |")
    md.append("| --- | --- | --- | --- | --- |")
    for i, item in enumerate(files, 1):
        kinds = "、".join("%s×%d" % (k, v)
                         for k, v in sorted(item["cwe"].items(), key=lambda kv: -kv[1]))
        md.append("| %d | %s | %d | %s | %d |"
                  % (i, item["file"], item["defects"], kinds or "-", item["hints"]))
    md.append("")

    detail = [f for f in files if f["defects"]]
    if detail:
        md.append("## 缺陷明细")
        md.append("")
        for i, item in enumerate(detail, 1):
            md.append("### %d. %s" % (i, item["file"]))
            md.append("")
            for d in item["items"]:
                addr = "、".join(d["addresses"]) if d["addresses"] else "-"
                md.append("- `%s` @ `%s`：%s" % (d["name"], addr, d["description"]))
            md.append("")

    (cwe_dir / "summary.md").write_text("\n".join(md), encoding="utf-8")

    # ---- stdout ----
    print("[i] CWE 扫描 %d 个文件：有缺陷发现 %d 个，仅 CWE676 提示 %d 个，无发现 %d 个"
          % (scanned, with_defects, hint_only, no_findings))
    if by_cwe:
        top = sorted(by_cwe.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
        print("[i] 缺陷发现 %d 条：%s" % (defect_total,
              "、".join("%s×%d" % (k, v) for k, v in top)))
    else:
        print("[i] 未发现任何 CWE 缺陷")
    if hint_total:
        print("[i] CWE676 危险符号提示 %d 条（仅提示，不计入缺陷）" % hint_total)
    for item in detail[:10]:
        print("    - %s：%d 条（%s）" % (item["file"], item["defects"],
              "、".join(sorted(item["cwe"]))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
