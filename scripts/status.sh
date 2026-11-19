#!/bin/sh
# 查看流水线各步骤的完成状态与产物数量（POSIX sh，可直接 sh 运行）
# 用法: status.sh [输出目录]（默认 /work/out）
set -u
OUT_DIR="${1:-/work/out}"
STATE="$OUT_DIR/.state"

printf '输出目录: %s\n\n' "$OUT_DIR"
printf '%-4s %-14s %-8s %-26s %s\n' "步骤" "名称" "状态" "完成时间" "产物"
i=1
while [ "$i" -le 8 ]; do
  case "$i" in
    1) name="组件CVE"; d="01_cve" ;;
    2) name="能力特征"; d="02_capa" ;;
    3) name="CWE缺陷"; d="03_cwe" ;;
    4) name="反编译"; d="04_pseudocode" ;;
    5) name="伪代码规则"; d="05_semgrep" ;;
    6) name="污点分析"; d="06_joern" ;;
    7) name="脚本扫描"; d="07_script" ;;
    8) name="汇总"; d="" ;;
  esac
  if [ -f "$STATE/$i.done" ]; then
    st="[done]"
    t="$(cat "$STATE/$i.done" 2>/dev/null)"
  else
    st="[--]"
    t="-"
  fi
  if [ "$i" = "8" ]; then
    if [ -f "$OUT_DIR/高风险点清单.md" ]; then cnt="清单已生成"; else cnt="无"; fi
  else
    cnt="$(find "$OUT_DIR/$d" -type f 2>/dev/null | wc -l | tr -d ' ') 个文件"
  fi
  tool="$(cat "$STATE/$i.tool" 2>/dev/null || true)"
  printf '%-4s %-14s %-8s %-26s %s%s\n' "$i" "$name" "$st" "$t" "$cnt" "${tool:+  ($tool)}"
  i=$((i + 1))
done
