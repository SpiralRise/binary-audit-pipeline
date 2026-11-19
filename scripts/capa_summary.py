#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""汇总 capa 结果：哪些文件被命中、命中了哪些函数、命中了哪些规则。

用法: capa_summary.py <out_dir>
输入: <out_dir>/02_capa/*.json（capa -j 输出）
输出:
  02_capa/hits.json       机器可读（第 4 步据此挑选 Ghidra 反编译对象）
  02_capa/hit_files.txt   命中文件的绝对路径，一行一个
  02_capa/summary.md      人读汇总（文件 → 函数 → 规则）

说明: capa 的 JSON 里 meta.analysis.layout.functions 只有函数入口地址、没有符号名，
      因此函数名按 Ghidra 默认命名规则生成 FUN_<入口地址>，可直接在
      04_pseudocode/<同名文件>.c 中搜索。
"""
import json
import sys
from pathlib import Path


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            return json.load(fh)
    except Exception:
        return None


def addr_of(obj):
    """从 {"type":"absolute","value":N} 或整数里取地址。"""
    if isinstance(obj, dict):
        obj = obj.get("value")
    if isinstance(obj, bool):
        return None
    if isinstance(obj, int):
        return obj
    if isinstance(obj, str):
        try:
            return int(obj, 0)
        except ValueError:
            return None
    return None


def fmt_addr(value):
    return f"0x{value:x}" if isinstance(value, int) else str(value)


def collect_match_addrs(matches):
    """capa matches 结构: [[主命中位置, 规则节点...], ...]，只取每组第一个。"""
    addrs = []
    if not isinstance(matches, list):
        return addrs
    for group in matches:
        if isinstance(group, list) and group:
            a = addr_of(group[0])
            if a is not None:
                addrs.append(a)
    return sorted(set(addrs))


def func_index(layout):
    """layout.functions -> [(入口地址, 函数字典)]，按地址升序。"""
    funcs = []
    for item in ((layout or {}).get("functions") or []):
        if not isinstance(item, dict):
            continue
        a = addr_of(item.get("address"))
        if a is not None:
            funcs.append((a, item))
    funcs.sort(key=lambda pair: pair[0])
    return funcs


def find_func(funcs, addr):
    """二分查找不大于 addr 的最近函数入口（capa 不提供函数结束地址，取最近入口）。"""
    lo, hi, best = 0, len(funcs) - 1, None
    while lo <= hi:
        mid = (lo + hi) // 2
        if funcs[mid][0] <= addr:
            best = funcs[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    return best


def func_label(func):
    name = str(func.get("name") or "").strip()
    if name:
        return name
    a = addr_of(func.get("address"))
    if a is None:
        return "(未知函数)"
    return f"FUN_{a:08x}" if a < 0x100000000 else f"FUN_{a:016x}"


def main():
    if len(sys.argv) < 2:
        print("usage: capa_summary.py <out_dir>", file=sys.stderr)
        return 2
    out_dir = Path(sys.argv[1])
    capa_dir = out_dir / "02_capa"
    capa_dir.mkdir(parents=True, exist_ok=True)

    analyzed = 0
    files = []
    for path in sorted(capa_dir.glob("*.json")):
        if path.name in ("hits.json",):
            continue
        data = load_json(path)
        if not isinstance(data, dict):
            continue
        rules = data.get("rules")
        if not isinstance(rules, dict) or not rules:
            continue
        analyzed += 1

        meta = data.get("meta") or {}
        sample = meta.get("sample") or {}
        file_path = str(sample.get("path") or "").strip()
        analysis = meta.get("analysis") or {}
        funcs = func_index(analysis.get("layout"))

        rule_rows = []
        func_map = {}
        for rule_key, rule_data in rules.items():
            rmeta = (rule_data or {}).get("meta") or {}
            rule_name = str(rmeta.get("name") or rule_key)
            namespace = str(rmeta.get("namespace") or "other")
            addrs = collect_match_addrs((rule_data or {}).get("matches"))
            labels = []
            for a in addrs:
                hit = find_func(funcs, a)
                if hit:
                    faddr, fobj = hit
                    label = func_label(fobj)
                else:
                    label = "(未知函数)"
                    faddr = a
                labels.append(label)
                entry = func_map.setdefault(
                    label,
                    {"name": label, "address": fmt_addr(faddr),
                     "rules": set(), "addresses": set()},
                )
                entry["rules"].add(f"{rule_name} [{namespace}]")
                entry["addresses"].add(fmt_addr(a))
            rule_rows.append({
                "rule": rule_name,
                "namespace": namespace,
                "addresses": [fmt_addr(a) for a in addrs],
                "functions": sorted(set(labels)),
            })

        functions = []
        for label, entry in func_map.items():
            functions.append({
                "name": label,
                "address": entry["address"],
                "rules": sorted(entry["rules"]),
                "addresses": sorted(entry["addresses"]),
            })
        functions.sort(key=lambda item: item["address"])

        files.append({
            "path": file_path or f"(未知路径) {path.stem}",
            "capa_json": path.name,
            "rule_count": len(rule_rows),
            "function_count": len(functions),
            "functions": functions,
            "rules": rule_rows,
        })

    files.sort(key=lambda item: (-item["rule_count"], item["path"]))

    # ---- hits.json ----
    hits = {"analyzed_files": analyzed, "hit_files": len(files), "files": files}
    (capa_dir / "hits.json").write_text(
        json.dumps(hits, ensure_ascii=False, indent=2), encoding="utf-8")

    # ---- hit_files.txt ----
    real_paths = [f["path"] for f in files if not f["path"].startswith("(未知路径)")]
    (capa_dir / "hit_files.txt").write_text(
        "\n".join(real_paths) + ("\n" if real_paths else ""), encoding="utf-8")

    # ---- summary.md ----
    lines = [
        "# capa 能力命中汇总（哪些文件 → 哪些函数 → 哪些规则）",
        "",
        f"- 有命中的文件数：{len(files)}（capa JSON 数：{analyzed}）",
        "- 函数名说明：capa 不提供符号名时按 Ghidra 默认命名 `FUN_<函数入口地址>` 生成，",
        "  可直接在 `04_pseudocode/<同名文件>.c` 中搜索该名字。",
        "- 注意：capa 与 Ghidra 是两套独立分析，函数起始地址可能略有差异；",
        "  若伪代码里找不到同名函数，用下表的“命中地址”在伪代码中搜索对应地址。",
        "- 机器可读清单：`02_capa/hits.json`；命中文件路径：`02_capa/hit_files.txt`",
        "",
        "## 文件总览",
        "",
        "| # | 文件 | 命中规则数 | 命中函数数 |",
        "| --- | --- | --- | --- |",
    ]
    if files:
        for i, item in enumerate(files, 1):
            lines.append(f"| {i} | `{item['path']}` | {item['rule_count']} | {item['function_count']} |")
    else:
        lines.append("| - | （没有文件命中任何 capa 规则） | 0 | 0 |")

    lines += ["", "## 文件明细", ""]
    for i, item in enumerate(files, 1):
        lines.append(f"### {i}. {Path(item['path']).name}")
        lines.append("")
        lines.append(f"- 路径：`{item['path']}`")
        lines.append(f"- 命中 {item['rule_count']} 条规则，涉及 {item['function_count']} 个函数")
        lines.append("")
        if item["functions"]:
            lines.append("| 函数 | 命中规则（能力域） | 命中地址 |")
            lines.append("| --- | --- | --- |")
            for func in item["functions"]:
                rule_text = "<br>".join(func["rules"][:12])
                if len(func["rules"]) > 12:
                    rule_text += f"<br>...（另 {len(func['rules']) - 12} 条）"
                lines.append(
                    f"| `{func['name']}` | {rule_text} | {', '.join(func['addresses'])} |")
        else:
            lines.append("（规则命中位置无法归属到函数，可能该文件不是可分析的可执行格式）")
        lines.append("")

    (capa_dir / "summary.md").write_text("\n".join(lines), encoding="utf-8")

    print(f"capa 汇总完成：命中文件 {len(files)} 个 -> {capa_dir / 'summary.md'}")
    for item in files[:20]:
        print(f"  - {item['path']}（{item['rule_count']} 规则 / {item['function_count']} 函数）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
