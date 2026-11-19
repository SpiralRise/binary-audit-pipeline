#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""挑选需要 Ghidra 反编译的文件：只取 capa 与 cwe_checker 命中的文件。

用法: select_reverse_targets.py <out_dir> <target_dir> [max_mb]
输出: stdout 每行一个文件绝对路径（已去重、已过滤体积）
诊断: stderr

判定“命中”:
  - capa:     02_capa/hits.json 里的文件；若无 hits.json，则 02_capa/*.json 中 rules 非空
  - cwe_checker: 03_cwe/<文件名>.txt 末尾 JSON 里有「非 CWE676」的缺陷发现
                 （CWE676 只是“使用了危险函数”的提示，几乎每个 ELF 都有，不算命中）
"""
import json
import os
import re
import sys
from pathlib import Path

CWE_RE = re.compile(r"\bCWE\d{2,4}\b")


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except Exception:
        return None


def capa_hit_paths(out_dir):
    paths = set()
    hits_json = out_dir / "02_capa" / "hits.json"
    data = load_json(hits_json)
    if isinstance(data, dict):
        for item in data.get("files") or []:
            p = str((item or {}).get("path") or "").strip()
            if p:
                paths.add(p)
        return paths

    # 兼容旧输出目录：没有 hits.json 时直接读 capa JSON
    for path in sorted((out_dir / "02_capa").glob("*.json")):
        d = load_json(path)
        if not isinstance(d, dict):
            continue
        rules = d.get("rules")
        if not isinstance(rules, dict) or not rules:
            continue
        p = str(((d.get("meta") or {}).get("sample") or {}).get("path") or "").strip()
        if p:
            paths.add(p)
    return paths


HINT_ONLY = {"CWE676"}


def load_cwe_findings(text):
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


def cwe_hit_info(out_dir):
    """返回 (有缺陷发现, 仅CWE676提示, 无发现) 三组文件名（不含 .txt）。"""
    defect, hint_only, empty = set(), set(), set()
    cwe_dir = out_dir / "03_cwe"
    if not cwe_dir.is_dir():
        return defect, hint_only, empty
    for path in cwe_dir.glob("*.txt"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        findings = load_cwe_findings(text)
        if findings is None:
            # 解析不了就保守处理：出现 CWE 编号即视为有发现
            if CWE_RE.search(text):
                defect.add(path.stem)
            else:
                empty.add(path.stem)
            continue
        names = [str(f.get("name") or "").strip()
                 for f in findings if isinstance(f, dict)]
        names = [n for n in names if n]
        if any(n not in HINT_ONLY for n in names):
            defect.add(path.stem)
        elif names:
            hint_only.add(path.stem)
        else:
            empty.add(path.stem)
    return defect, hint_only, empty


def build_basename_index(target_dir):
    index = {}
    for root, _dirs, files in os.walk(target_dir):
        for name in files:
            index.setdefault(name, []).append(os.path.join(root, name))
    return index


def resolve(path_str, index):
    if path_str and os.path.isfile(path_str):
        return os.path.abspath(path_str)
    base = os.path.basename(path_str) if path_str else ""
    candidates = index.get(base) or []
    return os.path.abspath(candidates[0]) if candidates else None


def main():
    if len(sys.argv) < 3:
        print("usage: select_reverse_targets.py <out_dir> <target_dir> [max_mb]",
              file=sys.stderr)
        return 2
    out_dir = Path(sys.argv[1])
    target_dir = sys.argv[2]
    max_mb = float(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else 200.0

    capa_paths = capa_hit_paths(out_dir)
    cwe_defect, cwe_hint, cwe_empty = cwe_hit_info(out_dir)

    # 只有拿不到真实路径（cwe 输出只有文件名，或 capa 记录的路径失效）时才遍历目标目录
    need_index = bool(cwe_defect) or any(not os.path.isfile(p) for p in capa_paths)
    index = build_basename_index(target_dir) if need_index else {}

    chosen = set()
    capa_found = 0
    for p in capa_paths:
        real = resolve(p, index)
        if real:
            chosen.add(real)
            capa_found += 1

    cwe_found = 0
    for name in cwe_defect:
        candidates = index.get(name) or []
        if candidates:
            chosen.add(os.path.abspath(candidates[0]))
            cwe_found += 1

    kept = []
    too_small = too_big = 0
    for path in sorted(chosen):
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        if size < 1024:
            too_small += 1
            continue
        if max_mb > 0 and size > max_mb * 1024 * 1024:
            too_big += 1
            continue
        kept.append(path)

    notes = []
    if too_small:
        notes.append(f"跳过 <1KB {too_small} 个")
    if too_big:
        notes.append(f"跳过 >{max_mb:g}MB {too_big} 个")
    msg = (f"[i] capa 命中 {len(capa_paths)} 个文件（可定位 {capa_found}）；"
           f"cwe 有缺陷发现 {len(cwe_defect)} 个（可定位 {cwe_found}）"
           f"，另有仅 CWE676 提示 {len(cwe_hint)} 个、无发现 {len(cwe_empty)} 个；"
           f"合并去重 {len(chosen)} 个，进入反编译 {len(kept)} 个")
    if notes:
        msg += "（" + "，".join(notes) + "）"
    print(msg, file=sys.stderr)

    for path in kept:
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
