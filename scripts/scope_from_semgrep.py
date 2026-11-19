#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 Semgrep 命中的伪代码文件整份拷进 06_joern/scope/，供 Joern 只对命中文件建图。

用法: scope_from_semgrep.py <out_dir>
产物:
  06_joern/scope/<原文件名>.c     命中的伪代码文件（整份拷贝，不截断，避免切断跨函数数据流）
  06_joern/semgrep_sinks.txt      从命中行提取的危险函数名（taint_scan.sc 优先读取）
"""
import json
import re
import shutil
import sys
from pathlib import Path

# 常见的非函数调用关键字，提取 sink 时排除
KEYWORDS = {
    "if", "for", "while", "switch", "return", "sizeof", "do", "else",
    "case", "goto", "defined", "static", "const", "unsigned", "signed", "long",
    "short", "int", "char", "void", "float", "double", "struct", "union", "enum",
}

CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except Exception:
        return None


def read_snippet(src, start, end):
    """读取命中行附近源码（Semgrep 的 extra.lines 在未登录时会返回占位文本）。"""
    try:
        lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return ""
    if not start:
        return ""
    lo = max(1, int(start))
    hi = min(len(lines), max(lo, int(end or lo)) + 3)
    return "\n".join(lines[lo - 1:hi])


def main():
    if len(sys.argv) < 2:
        print("usage: scope_from_semgrep.py <out_dir>", file=sys.stderr)
        return 2
    out_dir = Path(sys.argv[1])
    semgrep_json = out_dir / "05_semgrep" / "semgrep.json"
    scope_dir = out_dir / "06_joern" / "scope"
    sinks_file = out_dir / "06_joern" / "semgrep_sinks.txt"

    scope_dir.mkdir(parents=True, exist_ok=True)

    data = load_json(semgrep_json)
    results = (data or {}).get("results") or [] if isinstance(data, dict) else []

    copied = {}
    sinks = set()
    missing = 0
    for r in results:
        if not isinstance(r, dict):
            continue
        p = str(r.get("path") or "")
        if not p:
            continue
        # 路径兼容容器内绝对路径与相对路径
        src = Path(p)
        if not src.is_file():
            alt = out_dir / "04_pseudocode" / src.name
            if alt.is_file():
                src = alt
            else:
                missing += 1
                continue
        if src.name not in copied:
            dst = scope_dir / src.name
            try:
                shutil.copy2(src, dst)
                copied[src.name] = dst
            except Exception as exc:
                print(f"[warn] 拷贝失败 {src}: {exc}")
                continue
        # 从命中行（直接读源文件）提取被调用函数名，作为 sink 候选
        start = (r.get("start") or {}).get("line")
        end = (r.get("end") or {}).get("line")
        snippet = read_snippet(src, start, end)
        for m in CALL_RE.finditer(snippet):
            name = m.group(1)
            if name.lower() not in KEYWORDS and not name.startswith("FUN_"):
                sinks.add(name)

    if sinks:
        sinks_file.write_text("\n".join(sorted(sinks)) + "\n", encoding="utf-8")
    elif sinks_file.exists():
        sinks_file.unlink()

    print(f"scope 文件数: {len(copied)}，缺失路径: {missing}，sink 候选: {len(sinks)}")
    if sinks:
        print("sink 候选: " + ", ".join(sorted(sinks)[:20]))
    if not copied:
        print("[i] Semgrep 无命中，scope 为空（第 6 步将跳过；JOERN_FULL=1 可强制全量）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
