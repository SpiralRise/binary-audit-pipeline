#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把流水线各步骤的产物汇总成一份《高风险点清单.md》。

设计原则：对 JSON 结构做宽松提取，任何一个工具的输出格式变了或缺失，
都只是那一节变空，不会让整个汇总失败。
"""
import json
import os
import re
import sys
from pathlib import Path

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "ERROR": 1, "MEDIUM": 2, "WARNING": 2,
             "LOW": 3, "INFO": 4, "UNKNOWN": 5}


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except Exception:
        return None


def walk_find(obj, key_names, out, depth=0):
    """递归收集所有名为 key_names 之一的键值（宽松匹配）。"""
    if depth > 12:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in key_names:
                out.append(v)
            walk_find(v, key_names, out, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            walk_find(item, key_names, out, depth + 1)


def sec_cve(out_dir):
    lines = []
    path = out_dir / "01_cve" / "cve.json"
    data = load_json(path)
    if data is None:
        return ["（未生成 01_cve/cve.json，可能离线数据库未初始化）"], 0
    raw = []
    walk_find(data, {"vulnerabilities", "cve_list", "cves"}, raw)
    rows = []
    for chunk in raw:
        items = chunk if isinstance(chunk, list) else [chunk]
        for it in items:
            if isinstance(it, dict):
                name = (it.get("cve_number") or it.get("cve") or it.get("id")
                        or it.get("CVE") or "")
                sev = (it.get("severity") or it.get("score") or "UNKNOWN")
                comp = it.get("component") or it.get("product") or ""
                if name:
                    rows.append((str(sev).upper(), str(name), str(comp)))
    if not rows:
        lines.append("（JSON 已生成，但未解析出 CVE 条目，请直接查看 01_cve/cve.json）")
        return lines, 0
    rows.sort(key=lambda r: SEV_ORDER.get(r[0], 9))
    lines.append("| 严重级别 | CVE | 组件 |")
    lines.append("| --- | --- | --- |")
    for sev, name, comp in rows[:100]:
        lines.append(f"| {sev} | {name} | {comp} |")
    if len(rows) > 100:
        lines.append(f"\n（共 {len(rows)} 条，此处只列前 100 条）")
    return lines, len(rows)


def _capa_from_hits(data):
    """用 02_capa/hits.json 输出：文件表 + 每个文件命中的规则 + 函数（前 N 个）。"""
    files = data.get("files") or []
    rule_total = sum(int(f.get("rule_count") or 0) for f in files)
    lines = [f"- 有命中的文件：{len(files)} 个（规则命中总数 {rule_total}）", ""]
    lines.append("| # | 文件 | 命中规则数 | 命中函数数 |")
    lines.append("| --- | --- | --- | --- |")
    for i, f in enumerate(files, 1):
        lines.append("| %d | `%s` | %s | %s |"
                     % (i, f.get("path") or "?", f.get("rule_count", 0),
                        f.get("function_count", 0)))
    lines.append("")

    lines.append("### 命中的规则（按文件）")
    lines.append("")
    for f in files:
        rules = []
        for fn in f.get("functions") or []:
            for r in fn.get("rules") or []:
                if r not in rules:
                    rules.append(r)
        lines.append("- **%s**（%d 条）：%s"
                     % (os.path.basename(str(f.get("path") or "?")),
                        len(rules), "、".join(rules) or "-"))
    lines.append("")

    lines.append("### 命中的函数（每个文件最多 20 个，完整见 `02_capa/summary.md`）")
    lines.append("")
    for f in files:
        fns = f.get("functions") or []
        base = os.path.basename(str(f.get("path") or "?"))
        parts = []
        for fn in fns[:20]:
            name = fn.get("name") or fn.get("address") or "?"
            rs = fn.get("rules") or []
            parts.append("%s（%s）" % (name, rs[0] if rs else "-"))
        more = f" …共 {len(fns)} 个" if len(fns) > 20 else ""
        lines.append("- **%s**：%s%s" % (base, "、".join(parts) or "-", more))
    return lines


def sec_capa(out_dir):
    lines = []
    d = out_dir / "02_capa"
    if not d.exists():
        return ["（未生成）"], 0

    # 优先用 capa_summary.py 生成的 hits.json（含文件→函数→规则）
    data = load_json(d / "hits.json")
    if isinstance(data, dict) and data.get("files"):
        return _capa_from_hits(data) + [""], sum(
            int(f.get("rule_count") or 0) for f in data["files"])

    hits = {}
    hit_files = []
    for p in sorted(d.glob("*.json")):
        if p.name == "hits.json":
            continue
        data = load_json(p)
        if not isinstance(data, dict):
            continue
        rules = data.get("rules") or {}
        if not isinstance(rules, dict):
            continue
        if rules:
            hit_files.append(p.stem)
        for rname, rdata in rules.items():
            meta = (rdata or {}).get("meta") or {}
            ns = meta.get("namespace") or "other"
            display = meta.get("name") or rname
            hits.setdefault(ns, []).append((p.stem, display))
    total = sum(len(v) for v in hits.values())
    if not hits:
        return ["（未命中能力规则）"], 0
    lines.append(f"- 有命中的文件：{len(hit_files)} 个，"
                 "文件→函数→规则明细见 `02_capa/summary.md`（机器可读：`02_capa/hits.json`）")
    if hit_files:
        shown = "、".join(hit_files[:15])
        more = f" 等 {len(hit_files)} 个" if len(hit_files) > 15 else ""
        lines.append(f"- 命中文件：{shown}{more}")
    interesting = ("file", "load-code", "host-interaction", "data-manipulation",
                   "communication", "crypto", "executable")
    ordered = [k for k in sorted(hits) if any(k.startswith(i) for i in interesting)]
    ordered += [k for k in sorted(hits) if k not in ordered]
    for ns in ordered[:20]:
        lines.append(f"- {ns}：{len(hits[ns])} 条命中，例：{hits[ns][0][1]}")
    return lines, total


def sec_cwe(out_dir):
    lines = []
    d = out_dir / "03_cwe"
    if not d.exists():
        return ["（未生成）"], 0

    # 优先用 cwe_summary.py 生成的汇总（已把 CWE676 提示与真正的缺陷分开）
    data = load_json(d / "findings.json")
    if isinstance(data, dict):
        total = int(data.get("defect_total") or 0)
        lines.append(
            "- 扫描 ELF %s 个：**有缺陷发现 %s 个**，仅 CWE676 提示 %s 个，无任何发现 %s 个"
            % (data.get("scanned", 0), data.get("with_defects", 0),
               data.get("hint_only", 0), data.get("no_findings", 0)))
        by_cwe = data.get("by_cwe") or {}
        if by_cwe:
            top = sorted(by_cwe.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
            lines.append("- 缺陷类型：" + "、".join("%s×%d" % (k, v) for k, v in top))
        if data.get("hint_total"):
            lines.append("- CWE676 危险符号提示 %s 条（仅提示，不计入缺陷）"
                         % data["hint_total"])
        shown = 0
        for item in data.get("files") or []:
            if not item.get("defects"):
                continue
            shown += 1
            if shown > 30:
                break
            kinds = "、".join("%s×%d" % (k, v)
                             for k, v in sorted((item.get("cwe") or {}).items(),
                                                key=lambda kv: -kv[1]))
            lines.append("- %s：%d 条（%s）" % (item.get("file"), item["defects"], kinds))
        if not shown:
            lines.append("- 未发现任何 CWE 缺陷（只有工具日志与 CWE676 提示）")
        return lines, total

    # 回退：旧输出目录没有 findings.json，直接解析 cwe_checker 原始 txt
    total = 0
    for p in sorted(d.glob("*.txt")):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        ids = sorted(set(re.findall(r"CWE\d{2,4}", text)),
                     key=lambda x: int(x[3:]))
        if ids:
            total += len(ids)
            lines.append(f"- {p.stem}：{', '.join(ids)}")
    if not lines:
        lines.append("（未发现 CWE 告警，或输出格式与预期不同，见 03_cwe/ 原始文件）")
    return lines, total


def sec_pseudo(out_dir):
    d = out_dir / "04_pseudocode"
    if not d.exists():
        return ["（未生成）"], 0
    files = sorted(d.glob("*.c"))
    total_funcs = 0
    lines = []
    for p in files:
        try:
            n = p.read_text(encoding="utf-8", errors="replace").count("// ===== function")
        except Exception:
            n = 0
        total_funcs += n
        lines.append(f"- {p.name}：{n} 个函数")
    if not lines:
        lines.append("（未生成伪代码）")
    lines.append(f"\n合计 {len(files)} 个文件、{total_funcs} 个函数。")
    return lines, total_funcs


def sec_semgrep(out_dir):
    path = out_dir / "05_semgrep" / "semgrep.json"
    data = load_json(path)
    if not isinstance(data, dict):
        return ["（未生成 05_semgrep/semgrep.json）"], 0
    results = data.get("results") or []
    rows = []
    for r in results:
        if not isinstance(r, dict):
            continue
        rows.append((str((r.get("extra") or {}).get("severity", "WARNING")).upper(),
                     r.get("check_id", ""),
                     os.path.basename(str(r.get("path", ""))),
                     str((r.get("start") or {}).get("line", "?"))))
    rows.sort(key=lambda r: SEV_ORDER.get(r[0], 9))
    lines = []
    if rows:
        lines.append("| 级别 | 规则 | 文件 | 行 |")
        lines.append("| --- | --- | --- | --- |")
        for sev, cid, fname, line in rows[:200]:
            lines.append(f"| {sev} | {cid} | {fname} | {line} |")
        if len(rows) > 200:
            lines.append(f"\n（共 {len(rows)} 条，此处只列前 200 条）")
    else:
        lines.append("（未命中规则）")
    errs = data.get("errors") or []
    if errs:
        lines.append(f"\n[i] Semgrep 解析告警 {len(errs)} 条（伪代码常含非标准类型，属正常）")
    return lines, len(rows)


def sec_joern(out_dir):
    p = out_dir / "06_joern" / "taint_flows.txt"
    if not p.exists():
        return ["（未生成。Joern 为可选步骤，用 WITH_JOERN=1 打开）"], 0
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ["（读取失败）"], 0
    raw = text.splitlines()
    flows = [ln for ln in raw if ln.startswith("## flow")]
    files = [ln[len("#   文件: "):].strip()
             for ln in raw if ln.startswith("#   文件:")]
    sinks = [ln for ln in raw if ln.startswith("  - ")]

    lines = []
    for ln in raw:
        if ln.startswith("# 注意") or ln.startswith("# 节点格式"):
            continue
        if ln.startswith("# 污点可达路径数") or ln.startswith("# 已过滤") \
                or ln.startswith("# 汇总") or ln.startswith("# sink 名单来源"):
            lines.append("- " + ln[2:].strip())
        elif ln.startswith("# sink 名单("):
            count = ln.split("(", 1)[1].split(")", 1)[0]
            lines.append("- sink 名单：%s 个（明细见 `06_joern/taint_flows.txt` 头部）" % count)
    if files:
        lines.append("- 涉及文件（%d 个）：%s" % (len(files), "、".join(files)))

    # ---- sink 命中清单：总量按文件统计 + 单独列出危险调用 ----
    sink_re = re.compile(r'^  - ([\w.\-]+\.c):(\d+)\s+(\S+)\s+\|\s+(.*)$')
    danger_re = re.compile(
        r'\b(memcpy|memmove|strcpy|strcat|sprintf|vsprintf|sscanf|system|popen|'
        r'exec[lv]p?e?|gets|scanf)\b')
    per_file = {}
    danger = []
    for ln in sinks:
        m = sink_re.match(ln)
        if not m:
            continue
        fname, lineno, func, code = m.groups()
        per_file[fname] = per_file.get(fname, 0) + 1
        if danger_re.search(code):
            danger.append((fname, lineno, func, code))
    if sinks:
        lines.append("- sink 命中清单：**%d 条**，分布在 %d 个文件（全量见 "
                     "`06_joern/taint_flows.txt` 末尾）" % (len(sinks), len(per_file)))
        if per_file:
            top = sorted(per_file.items(), key=lambda kv: (-kv[1], kv[0]))
            lines.append("- sink 按文件：" + "、".join("%s %d 条" % (k, v) for k, v in top))
        lines.append("- 其中危险调用（memcpy/strcpy/system/exec 等）：**%d 条**，见 6.2"
                     % len(danger))

    # ---- 数据流：按起点文件分组 ----
    flow_re = re.compile(r'^## flow (\d+)（(\d+) 个节点）\s+从 (.+?)\s+到 (.+)$')
    part_re = re.compile(r'([\w.\-]+\.c):(\d+)\s+(\S+)')

    def short(part):
        m = part_re.match(part)
        if not m:
            return "未知", part[:80]
        return m.group(1), "%s:%s %s" % (m.group(1), m.group(2), m.group(3))

    groups = {}
    for idx, ln in enumerate(flows, 1):
        m = flow_re.match(ln)
        if m:
            key, start = short(m.group(3))
            _, end = short(m.group(4))
        else:
            key, start, end = "未知", ln[:80], ""
        groups.setdefault(key, []).append((idx, start, end))

    if flows:
        lines.append("")
        lines.append("### 6.1 数据流（按起点文件分组，共 %d 条）" % len(flows))
        for key in sorted(groups, key=lambda k: (-len(groups[k]), k)):
            items = groups[key]
            lines.append("")
            lines.append("#### %s（%d 条）" % (key, len(items)))
            lines.append("")
            lines.append("| # | 起点 | 终点 |")
            lines.append("| --- | --- | --- |")
            for idx, start, end in items:
                lines.append("| %d | %s | %s |" % (idx, start, end))
    else:
        lines.append("（未产出数据流，见 06_joern/taint_flows.txt 与 logs/06_joern.log）")

    # ---- 危险 sink 调用明细 ----
    if danger:
        lines.append("")
        lines.append("### 6.2 危险 sink 调用（%d 条，含 memcpy/strcpy/system 等）" % len(danger))
        lines.append("")
        lines.append("| # | 位置 | 函数 | 调用 |")
        lines.append("| --- | --- | --- | --- |")
        for i, (fname, lineno, func, code) in enumerate(danger[:200], 1):
            lines.append("| %d | %s:%s | %s | `%s` |"
                         % (i, fname, lineno, func,
                            code.replace("|", "\\|")[:140]))
        if len(danger) > 200:
            lines.append("\n（共 %d 条，此处只列前 200 条）" % len(danger))
    return lines, len(flows)


def _walk_dicts(obj, depth=0):
    if depth > 12:
        return
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _walk_dicts(v, depth + 1)
    elif isinstance(obj, list):
        for it in obj:
            yield from _walk_dicts(it, depth + 1)


def sec_script(out_dir):
    """第 7 步：脚本静态扫描（semgrep / bandit / njsscan），结构不固定，全部宽松解析。"""
    d = out_dir / "07_script"
    if not d.exists():
        return ["（未生成）"], 0
    rows = []

    data = load_json(d / "semgrep_script.json")
    if isinstance(data, dict):
        for r in data.get("results") or []:
            if not isinstance(r, dict):
                continue
            sev = str((r.get("extra") or {}).get("severity", "WARNING")).upper()
            rows.append((sev, "semgrep", str(r.get("check_id", ""))[:100],
                         os.path.basename(str(r.get("path", ""))),
                         str((r.get("start") or {}).get("line", "?"))))

    data = load_json(d / "bandit.json")
    if isinstance(data, dict):
        for r in data.get("results") or []:
            if not isinstance(r, dict):
                continue
            sev = str(r.get("issue_severity", "UNKNOWN")).upper()
            title = f"{r.get('test_id', '')} {str(r.get('issue_text', ''))[:80]}".strip()
            rows.append((sev, "bandit", title,
                         os.path.basename(str(r.get("filename", ""))),
                         str(r.get("line_number", "?"))))

    data = load_json(d / "njsscan.json")
    if isinstance(data, (dict, list)):
        for it in _walk_dicts(data):
            title = it.get("title") or it.get("message") or it.get("issue_text")
            sev = it.get("severity") or it.get("issue_severity")
            fname = (it.get("filename") or it.get("file") or it.get("file_path")
                     or it.get("path"))
            if title and sev and fname:
                line = it.get("line_number") or it.get("line") or "?"
                rows.append((str(sev).upper(), "njsscan", str(title)[:100],
                             os.path.basename(str(fname)), str(line)))

    rows.sort(key=lambda r: SEV_ORDER.get(r[0], 9))
    lines = []
    if rows:
        lines.append("| 级别 | 工具 | 问题 | 文件 | 行 |")
        lines.append("| --- | --- | --- | --- | --- |")
        for sev, tool, title, fname, line in rows[:100]:
            lines.append(f"| {sev} | {tool} | {title} | {fname} | {line} |")
        if len(rows) > 100:
            lines.append(f"\n（共 {len(rows)} 条，此处只列前 100 条）")
    else:
        lines.append("（未命中，或 07_script/ 下没有可用结果）")
    return lines, len(rows)


def main():
    if len(sys.argv) < 2:
        print("usage: summarize.py <out_dir>", file=sys.stderr)
        return 2
    out_dir = Path(sys.argv[1])

    sections = [
        ("1. 组件 CVE（cve-bin-tool，默认关闭）", sec_cve),
        ("2. 能力特征（capa）", sec_capa),
        ("3. CWE 缺陷（cwe_checker）", sec_cwe),
        ("4. 反编译产物（Ghidra，默认只反编译命中文件）", sec_pseudo),
        ("5. 伪代码规则命中（Semgrep）", sec_semgrep),
        ("6. 污点可达路径（Joern）", sec_joern),
        ("7. 脚本静态扫描（semgrep/bandit/njsscan）", sec_script),
    ]

    body = ["# 无源码二进制审计 · 高风险点清单", "",
            f"- 输出目录：`{out_dir}`", "- 生成方式：`scripts/pipeline.sh` 自动汇总", ""]

    summary_rows = []
    for title, func in sections:
        lines, count = func(out_dir)
        summary_rows.append((title, count))
        body.append(f"## {title}")
        body.append("")
        body.extend(lines)
        body.append("")

    body.insert(4, "")
    body.insert(4, "| 步骤 | 命中/产出数量 |")
    body.insert(5, "| --- | --- |")
    for i, (title, count) in enumerate(summary_rows):
        body.insert(6 + i, f"| {title} | {count} |")

    body += [
        "## 下一步怎么用",
        "",
        "1. 优先看第 5 节的 Semgrep 命中：那里的 `文件 + 行号` 直接对应伪代码位置，可跳到",
        "   `04_pseudocode/<程序名>.c` 里对应行确认真伪。",
        "2. 第 3 节的 CWE 告警给出地址，可用 Ghidra 打开目标跳到该地址核对。",
        "3. 确认是外部输入可控的危险调用后，把该函数作为 Fuzz 入口做针对性测试。",
        "4. 所有命中都需要人工或 AI 二次确认，静态结果本身不等于可利用漏洞。",
        "",
    ]

    out_file = out_dir / "高风险点清单.md"
    out_file.write_text("\n".join(body), encoding="utf-8")
    print(f"summary written: {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
