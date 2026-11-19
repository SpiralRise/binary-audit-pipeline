#!/usr/bin/env bash
# ============================================================
# 无源码二进制静态审计流水线 —— 容器内主流程（8 步）
# 1 CVE(默认关) → 2 能力 → 3 CWE → 4 反编译(只反编译命中文件)
# → 5 伪代码规则 → 6 污点(带文件/函数/行号/代码) → 7 脚本静态扫描 → 8 汇总
# 用法（容器内）：pipeline.sh
# 环境变量：
#   TARGET_DIR   待分析目录（默认 /work/targets）
#   OUT_DIR      输出目录（默认 /work/out）
#   JOBS         并行度（默认 CPU 核数）
#   WITH_CVEBIN / WITH_CAPA / WITH_CWE / WITH_GHIDRA / WITH_JOERN   0|1，默认 0/1/1/1/0
#   GHIDRA_SCOPE hits=只反编译 capa/CWE 命中的文件（默认）；all=目标目录全部文件
#   SRC_DIR      脚本源码目录（默认 /work/src；不存在时在目标目录里找 .js/.ts/.py 所在目录）
#   EXTRA_RULES  追加的 Semgrep --config 值（空格分隔，默认空）
#   SEMGREP_SEVERITY  严重度过滤（逗号分隔，默认 ERROR,WARNING；ALL 关闭过滤）
#   RESUME       1=已完成且目标未变的步骤跳过（默认 1）
#   FORCE        1=强制重跑并清理对应输出（默认 0）
#   ONLY_STEP    只跑指定步骤，如 "1,5" 或 "3"（默认空）
#   START_STEP   从第几步开始跑（默认 0）
#   GHIDRA_CHUNK     每块反编译的文件数（默认 200）
#   GHIDRA_TIMEOUT   每块超时秒数（默认 3600）
#   JOERN_FULL   1=污点分析用全量伪代码（默认 0，只用 Semgrep 命中文件）
#   CAPA_RULES   capa 规则目录（默认 /opt/capa-rules）
#   MAX_FILE_MB  单文件体积上限，超过则跳过反编译（默认 200）
# ============================================================
set -uo pipefail

TARGET_DIR="${TARGET_DIR:-/work/targets}"
OUT_DIR="${OUT_DIR:-/work/out}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"
WITH_CVEBIN="${WITH_CVEBIN:-0}"
WITH_CAPA="${WITH_CAPA:-1}"
WITH_CWE="${WITH_CWE:-1}"
WITH_GHIDRA="${WITH_GHIDRA:-1}"
WITH_JOERN="${WITH_JOERN:-0}"
GHIDRA_SCOPE="${GHIDRA_SCOPE:-hits}"
SRC_DIR="${SRC_DIR:-/work/src}"
EXTRA_RULES="${EXTRA_RULES:-}"
SEMGREP_SEVERITY="${SEMGREP_SEVERITY:-ERROR,WARNING}"
RESUME="${RESUME:-1}"
FORCE="${FORCE:-0}"
ONLY_STEP="${ONLY_STEP:-}"
START_STEP="${START_STEP:-0}"
GHIDRA_CHUNK="${GHIDRA_CHUNK:-200}"
GHIDRA_TIMEOUT="${GHIDRA_TIMEOUT:-3600}"
JOERN_FULL="${JOERN_FULL:-0}"
PIPELINE_HOME="${PIPELINE_HOME:-/opt/pipeline}"
RULES_DIR="${RULES_DIR:-$PIPELINE_HOME/rules}"
GHIDRA_SCRIPTS="${GHIDRA_SCRIPTS:-$PIPELINE_HOME/ghidra_scripts}"
GHIDRA_HOME="${GHIDRA_HOME:-/opt/ghidra}"
CAPA_RULES="${CAPA_RULES:-/opt/capa-rules}"
MAX_FILE_MB="${MAX_FILE_MB:-200}"

mkdir -p "$OUT_DIR"/01_cve "$OUT_DIR"/02_capa "$OUT_DIR"/03_cwe \
         "$OUT_DIR"/04_pseudocode "$OUT_DIR"/05_semgrep "$OUT_DIR"/06_joern \
         "$OUT_DIR"/07_script "$OUT_DIR"/logs
LOGS="$OUT_DIR/logs"
STATE_DIR="$OUT_DIR/.state"
mkdir -p "$STATE_DIR"

# 目标目录指纹：文件相对路径 + 大小；目标变了就必须重跑（除非 RESUME=0）
FP="$(find "$TARGET_DIR" -type f -printf '%P %s\n' 2>/dev/null | sort | sha256sum | cut -c1-16)"

banner()  { printf '\n===== [%s] %s =====\n' "$1" "$2"; }
have()    { command -v "$1" >/dev/null 2>&1; }
ok()      { printf '  [OK] %s\n' "$1"; }
skip()    { printf '  [SKIP] %s\n' "$1"; }

# ---------- 状态/续跑 ----------
# step_enabled <序号>：ONLY_STEP / START_STEP 选择器
step_enabled() {
  [ "$1" -ge "$START_STEP" ] || return 1
  if [ -n "$ONLY_STEP" ]; then
    case ",$ONLY_STEP," in *",$1,"*) return 0;; *) return 1;; esac
  fi
  return 0
}
# step_done <序号>：RESUME=1 且目标未变且标记存在
step_done() {
  [ "$RESUME" = "1" ] && [ "$FORCE" != "1" ] || return 1
  [ -f "$STATE_DIR/$1.done" ] || return 1
  [ "$(cat "$STATE_DIR/$1.fp" 2>/dev/null)" = "$FP" ] || return 1
  return 0
}
mark_done() { # <序号> <工具版本>
  printf '%s\n' "$FP" > "$STATE_DIR/$1.fp"
  date -Is > "$STATE_DIR/$1.done"
  printf '%s\n' "${2:-}" > "$STATE_DIR/$1.tool"
}
# prepare_step <序号> <输出目录>：FORCE=1 或目标变了才清理，避免上次结果混入本次
prepare_step() {
  local prev=""
  [ -f "$STATE_DIR/$1.fp" ] && prev="$(cat "$STATE_DIR/$1.fp")"
  if [ "$FORCE" = "1" ] || { [ -n "$prev" ] && [ "$prev" != "$FP" ]; }; then
    rm -rf "$2"; mkdir -p "$2"
  fi
}
# gate <序号> <步骤名>：返回 0=执行，1=已完成后跳过，2=被选择器跳过
gate() {
  if ! step_enabled "$1"; then
    skip "按 ONLY_STEP/START_STEP 跳过（第 $1 步：$2）"; return 2
  fi
  if step_done "$1"; then
    skip "已完成且目标未变，RESUME 跳过（第 $1 步：$2）"; return 1
  fi
  return 0
}

# ---------- 0. 环境自检 ----------
banner "0/8" "环境自检"
{
  echo "time        : $(date -Is)"
  echo "target dir  : $TARGET_DIR"
  echo "output dir  : $OUT_DIR"
  echo "fingerprint : $FP"
  echo "jobs        : $JOBS"
  echo "resume/force: $RESUME/$FORCE  only=$ONLY_STEP start=$START_STEP"
  echo "python3     : $(python3 -V 2>&1 || echo missing)"
  echo "cve-bin-tool: $(have cve-bin-tool && cve-bin-tool --version 2>&1 | head -n1 || echo missing)"
  echo "capa        : $(have capa && echo present || echo missing)"
  echo "semgrep     : $(have semgrep && semgrep --version 2>/dev/null | head -n1 || echo missing)"
  echo "ghidra      : $([ -x "$GHIDRA_HOME/support/analyzeHeadless" ] && echo present || echo missing)"
  echo "joern       : $(have joern-parse && echo present || echo missing)"
  echo "cwe_checker : $(have cwe_checker && echo present || echo missing)"
  echo "bandit      : $(have bandit && echo present || echo missing)"
  echo "njsscan     : $(have njsscan && echo present || echo missing)"
} | tee "$LOGS/00_env.txt"

if [ ! -d "$TARGET_DIR" ]; then
  echo "[!] 目标目录不存在: $TARGET_DIR"; exit 1
fi
FILE_COUNT=$(find "$TARGET_DIR" -type f 2>/dev/null | wc -l)
echo "[i] 目标目录内文件数: $FILE_COUNT"
if [ "$FILE_COUNT" = "0" ]; then
  echo "[!] 目录内没有文件，退出"; exit 1
fi

# ---------- 1. 组件 CVE 扫描 ----------
banner "1/8" "组件 CVE 扫描 (cve-bin-tool，默认关闭；需要时 WITH_CVEBIN=1)"
gate 1 "组件 CVE" 
rc=$?
if [ $rc -eq 0 ]; then
  prepare_step 1 "$OUT_DIR/01_cve"
  if [ "$WITH_CVEBIN" = "1" ] && have cve-bin-tool; then
    CVE_EXTRA=""
    cve-bin-tool --help 2>&1 | grep -q -- '--parallel' && CVE_EXTRA="--parallel"
    timeout 7200 cve-bin-tool --offline ${CVE_EXTRA:+$CVE_EXTRA} \
        -f json -o "$OUT_DIR/01_cve/cve.json" "$TARGET_DIR" \
        > "$LOGS/01_cve.log" 2>&1
    if [ $? -eq 0 ]; then
      ok "离线扫描完成 -> 01_cve/cve.json"
    else
      echo "  [i] 离线数据库不可用，尝试联网更新后重试"
      timeout 7200 cve-bin-tool -u now ${CVE_EXTRA:+$CVE_EXTRA} \
          -f json -o "$OUT_DIR/01_cve/cve.json" "$TARGET_DIR" \
          >> "$LOGS/01_cve.log" 2>&1 \
        && ok "在线更新+扫描完成 -> 01_cve/cve.json" \
        || echo "  [SKIP] cve-bin-tool 失败，详见 $LOGS/01_cve.log"
    fi
    mark_done 1 "cve-bin-tool $(cve-bin-tool --version 2>&1 | head -n1)"
  else
    skip "未安装 cve-bin-tool 或已关闭（用 WITH_CVEBIN=1 打开）"
  fi
fi

# ---------- 2. 能力特征识别 ----------
banner "2/8" "能力特征识别 (capa) —— 找'解析/加密/网络/命令执行'这类攻击面"
gate 2 "能力特征"
rc=$?
if [ $rc -eq 0 ]; then
  prepare_step 2 "$OUT_DIR/02_capa"
  if [ "$WITH_CAPA" = "1" ] && have capa; then
    CAPA_ARGS=""
    [ -d "$CAPA_RULES" ] && CAPA_ARGS="-r $CAPA_RULES"
    count=0
    while IFS= read -r f; do
      base=$(basename "$f")
      out="$OUT_DIR/02_capa/${base}.json"
      if [ "$FORCE" != "1" ] && [ -s "$out" ]; then continue; fi
      timeout 900 capa $CAPA_ARGS -j "$f" > "$out" \
          2> "$LOGS/02_capa_${base}.err" \
        || rm -f "$out"
      count=$((count + 1))
    done < <(find "$TARGET_DIR" -type f -size +1k -size -"${MAX_FILE_MB}"M 2>/dev/null)
    ok "已尝试分析 $count 个文件 -> 02_capa/"
    # 汇总“哪些文件被命中、命中哪些函数”：02_capa/summary.md + hits.json + hit_files.txt
    if have python3; then
      python3 "$PIPELINE_HOME/scripts/capa_summary.py" "$OUT_DIR" \
        2>&1 | tee "$LOGS/02_capa_summary.log"
      [ -s "$OUT_DIR/02_capa/summary.md" ] \
        && ok "命中汇总 -> 02_capa/summary.md（文件 → 函数 → 规则）" \
        || echo "  [warn] capa 汇总失败，见 logs/02_capa_summary.log"
    fi
    mark_done 2 "capa"
  else
    skip "capa 未安装或已关闭"
  fi
fi

# ---------- 3. CWE 缺陷扫描（本地 cwe_checker，不再依赖 Docker） ----------
banner "3/8" "CWE 缺陷扫描 (cwe_checker，主要面向 ELF)"
gate 3 "CWE 缺陷"
rc=$?
if [ $rc -eq 0 ]; then
  prepare_step 3 "$OUT_DIR/03_cwe"
  if [ "$WITH_CWE" = "1" ] && have cwe_checker; then
    CWE_JSON=""
    cwe_checker --help 2>&1 | grep -q -- '--json' && CWE_JSON="--json"
    count=0
    while IFS= read -r f; do
      if file "$f" 2>/dev/null | grep -q 'ELF'; then
        base=$(basename "$f")
        out="$OUT_DIR/03_cwe/${base}.txt"
        if [ "$FORCE" != "1" ] && [ -s "$out" ]; then continue; fi
        timeout 1800 cwe_checker ${CWE_JSON:+$CWE_JSON} "$f" \
            > "$out" 2> "$LOGS/03_cwe_${base}.err" \
          || echo "  [!] cwe_checker 处理失败: $base"
        count=$((count + 1))
      fi
    done < <(find "$TARGET_DIR" -type f 2>/dev/null)
    ok "已扫描 $count 个 ELF 文件 -> 03_cwe/"
    # 汇总：区分真正的 CWE 缺陷 与 CWE676 危险符号提示 -> 03_cwe/summary.md + findings.json
    if have python3; then
      python3 "$PIPELINE_HOME/scripts/cwe_summary.py" "$OUT_DIR" \
        2>&1 | tee "$LOGS/03_cwe_summary.log"
      [ -s "$OUT_DIR/03_cwe/summary.md" ] \
        && ok "CWE 结果汇总 -> 03_cwe/summary.md（缺陷发现 / CWE676 提示 分开统计）" \
        || echo "  [warn] CWE 汇总失败，见 logs/03_cwe_summary.log"
    fi
    mark_done 3 "cwe_checker"
  else
    skip "未找到本地 cwe_checker 或已关闭"
  fi
fi

# ---------- 4. 批量反编译成 C 伪代码（分块） ----------
banner "4/8" "批量反编译 (Ghidra headless，每块 ${GHIDRA_CHUNK} 个文件)"
gate 4 "批量反编译"
rc=$?
if [ $rc -eq 0 ]; then
  if [ "$WITH_GHIDRA" = "1" ] && [ -x "$GHIDRA_HOME/support/analyzeHeadless" ]; then
    prepare_step 4 "$OUT_DIR/04_pseudocode"
    if [ "$FORCE" = "1" ]; then rm -rf "$OUT_DIR/ghidra_project"; fi
    CHUNK_DIR="$OUT_DIR/.ghidra_chunks"
    rm -rf "$CHUNK_DIR"; mkdir -p "$CHUNK_DIR"
    LIST="$CHUNK_DIR/files.txt"; : > "$LIST"

    # 反编译范围：默认只反编译 capa + cwe_checker 命中的文件（GHIDRA_SCOPE=all 可回退全量）
    RAW="$CHUNK_DIR/candidates.txt"; : > "$RAW"
    FALLBACK_ALL=0
    if [ "$GHIDRA_SCOPE" = "hits" ] && have python3; then
      python3 "$PIPELINE_HOME/scripts/select_reverse_targets.py" \
          "$OUT_DIR" "$TARGET_DIR" "$MAX_FILE_MB" \
          > "$RAW" 2> "$LOGS/04_scope.log"
      sed 's/^/  /' "$LOGS/04_scope.log" 2>/dev/null | head -n 5
      if [ ! -s "$RAW" ]; then
        echo "  [i] capa/CWE 无命中文件，本次回退为全量反编译"
        FALLBACK_ALL=1
      fi
    else
      [ "$GHIDRA_SCOPE" = "all" ] && echo "  [i] GHIDRA_SCOPE=all，反编译全部文件"
      FALLBACK_ALL=1
    fi

    if [ "$FALLBACK_ALL" = "1" ]; then
      find "$TARGET_DIR" -type f -size +1k -size -"${MAX_FILE_MB}"M 2>/dev/null | sort > "$RAW"
    fi

    while IFS= read -r f; do
      [ -z "$f" ] && continue
      [ -f "$f" ] || continue
      base="$(basename "$f")"
      if [ "$FORCE" != "1" ] && [ -s "$OUT_DIR/04_pseudocode/$base.c" ]; then continue; fi
      printf '%s\n' "$f" >> "$LIST"
    done < "$RAW"
    TOTAL=$(wc -l < "$LIST")
    echo "[i] 反编译候选 $(wc -l < "$RAW") 个，本次待反编译: $TOTAL"
    CHUNK_ID=0
    while [ "$(wc -l < "$LIST")" -gt 0 ]; do
      CHUNK_ID=$((CHUNK_ID + 1))
      CHUNKS="$CHUNK_DIR/c$CHUNK_ID"; mkdir -p "$CHUNKS"
      head -n "$GHIDRA_CHUNK" "$LIST" | while IFS= read -r f; do
        ln -sf "$f" "$CHUNKS/$(basename "$f")" 2>/dev/null
      done
      PROJ="$OUT_DIR/ghidra_project/c$CHUNK_ID"; mkdir -p "$PROJ"
      echo "  [i] 第 $CHUNK_ID 块..."
      timeout "$GHIDRA_TIMEOUT" "$GHIDRA_HOME/support/analyzeHeadless" \
          "$PROJ" auditproj \
          -import "$CHUNKS" \
          -recursive \
          -scriptPath "$GHIDRA_SCRIPTS" \
          -postScript ExportDecompiled.java "$OUT_DIR/04_pseudocode" \
          -deleteProject \
          -max-cpu "$JOBS" \
          >> "$LOGS/04_ghidra.log" 2>&1 \
        || echo "  [!] 第 $CHUNK_ID 块部分失败（正常现象，见 $LOGS/04_ghidra.log）"
      rm -rf "$PROJ" "$CHUNKS"
      tail -n "+$((GHIDRA_CHUNK + 1))" "$LIST" > "$LIST.tmp" && mv "$LIST.tmp" "$LIST"
    done
    rm -rf "$CHUNK_DIR"
    PSEUDO_COUNT=$(find "$OUT_DIR/04_pseudocode" -name '*.c' 2>/dev/null | wc -l)
    ok "反编译完成 -> 04_pseudocode/（伪代码文件数: $PSEUDO_COUNT）"
    mark_done 4 "ghidra"
  else
    skip "Ghidra 不可用或已关闭"
  fi
fi

# ---------- 5. 伪代码规则扫描 ----------
banner "5/8" "伪代码规则扫描 (Semgrep) —— 定位危险调用点"
gate 5 "伪代码规则"
rc=$?
if [ $rc -eq 0 ]; then
  PSEUDO_DIR="$OUT_DIR/04_pseudocode"
  prepare_step 5 "$OUT_DIR/05_semgrep"
  if have semgrep && [ -d "$PSEUDO_DIR" ] && [ -n "$(find "$PSEUDO_DIR" -name '*.c' -print -quit 2>/dev/null)" ]; then
    # 规则分层叠加：本地 → 第三方(0xdea/trailofbits) → 官方包；EXTRA_RULES 追加
    LOCAL_RULES="$RULES_DIR/local"
    [ -d "$LOCAL_RULES" ] || LOCAL_RULES="$RULES_DIR"
    RULE_ARGS=(--config "$LOCAL_RULES")
    # 第三方规则只取适用于反编译伪代码的子目录（仓库根目录混有 CI 配置等非规则 YAML）
    for tp in "$RULES_DIR/thirdparty/0xdea/rules/c" "$RULES_DIR/thirdparty/trailofbits/generic"; do
      [ -d "$tp" ] && RULE_ARGS+=(--config "$tp")
    done
    for pack in cwe-top-25 secrets sql-injection security-audit; do
      if [ -f "$RULES_DIR/official/$pack.yml" ]; then
        RULE_ARGS+=(--config "$RULES_DIR/official/$pack.yml")
      else
        RULE_ARGS+=(--config "p/$pack")
      fi
    done
    if [ -n "$EXTRA_RULES" ]; then
      for extra in $EXTRA_RULES; do RULE_ARGS+=(--config "$extra"); done
    fi

    # 严重度过滤：默认只报 ERROR + WARNING；SEMGREP_SEVERITY=ALL 关闭
    SEV_ARGS=()
    if [ "$SEMGREP_SEVERITY" != "ALL" ]; then
      OLD_IFS="$IFS"; IFS=','
      for sev in $SEMGREP_SEVERITY; do SEV_ARGS+=(--severity "$sev"); done
      IFS="$OLD_IFS"
    fi

    semgrep scan \
        "${RULE_ARGS[@]}" \
        "${SEV_ARGS[@]}" \
        --json \
        --output "$OUT_DIR/05_semgrep/semgrep.json" \
        --metrics=off \
        --jobs "$JOBS" \
        --exclude '*.json' \
        "$PSEUDO_DIR" \
        > "$LOGS/05_semgrep.log" 2>&1
    if [ $? -eq 0 ] || [ -s "$OUT_DIR/05_semgrep/semgrep.json" ]; then
      ok "规则扫描完成 -> 05_semgrep/semgrep.json"
      mark_done 5 "semgrep $(semgrep --version 2>/dev/null | head -n1)"
    else
      echo "  [SKIP] Semgrep 执行失败，详见 $LOGS/05_semgrep.log"
    fi
  else
    skip "无伪代码或 Semgrep 不可用"
  fi
fi

# ---------- 6. 污点分析（只对 Semgrep 命中文件建图） ----------
banner "6/8" "污点可达性分析 (Joern，只分析命中文件)"
gate 6 "污点分析"
rc=$?
if [ $rc -eq 0 ]; then
  prepare_step 6 "$OUT_DIR/06_joern"
  if have python3; then
    python3 "$PIPELINE_HOME/scripts/scope_from_semgrep.py" "$OUT_DIR" \
      > "$LOGS/06_scope.log" 2>&1 || echo "  [warn] scope 生成失败，见 06_scope.log"
  fi
  SCOPE_DIR="$OUT_DIR/06_joern/scope"
  if [ "$WITH_JOERN" = "1" ] && have joern-parse; then
    if [ "$JOERN_FULL" = "1" ]; then
      PARSE_DIR="$OUT_DIR/04_pseudocode"
      echo "  [i] JOERN_FULL=1，使用全量伪代码"
    elif [ -d "$SCOPE_DIR" ] && [ -n "$(find "$SCOPE_DIR" -name '*.c' -print -quit 2>/dev/null)" ]; then
      PARSE_DIR="$SCOPE_DIR"
      echo "  [i] scope 文件数: $(find "$SCOPE_DIR" -name '*.c' | wc -l)"
    else
      skip "Semgrep 命中为空，第 6 步跳过（JOERN_FULL=1 可强制全量）"
      PARSE_DIR=""
    fi
    if [ -n "$PARSE_DIR" ]; then
      joern-parse --list-languages > "$LOGS/06_joern_langs.txt" 2>&1 || true
      if joern-parse "$PARSE_DIR" --language c \
            -o "$OUT_DIR/06_joern/cpg.bin" > "$LOGS/06_joern_parse.log" 2>&1; then
        CPG_FILE="$OUT_DIR/06_joern/cpg.bin" \
        JOERN_OUT="$OUT_DIR/06_joern/taint_flows.txt" \
        JOERN_SINKS="$OUT_DIR/06_joern/semgrep_sinks.txt" \
          joern --script "$PIPELINE_HOME/scripts/taint_scan.sc" \
          > "$LOGS/06_joern.log" 2>&1 \
          && ok "污点分析完成 -> 06_joern/taint_flows.txt" \
          || echo "  [SKIP] 污点查询失败（脚本 API 随版本变动），CPG 已保留"
        mark_done 6 "joern $(joern-parse --version 2>/dev/null | head -n1)"
      else
        echo "  [SKIP] CPG 构建失败，详见 $LOGS/06_joern_parse.log"
      fi
    fi
  else
    skip "Joern 不可用或已关闭（用 WITH_JOERN=1 打开）"
  fi
fi

# ---------- 7. 脚本静态扫描（JS/TS/Python） ----------
banner "7/8" "脚本静态扫描 (semgrep + bandit + njsscan)"
gate 7 "脚本扫描"
rc=$?
if [ $rc -eq 0 ]; then
  prepare_step 7 "$OUT_DIR/07_script"
  SCAN_DIR=""
  if [ -d "$SRC_DIR" ] && [ -n "$(find "$SRC_DIR" -type f \( -name '*.js' -o -name '*.ts' -o -name '*.py' \) -print -quit 2>/dev/null)" ]; then
    SCAN_DIR="$SRC_DIR"
  else
    f=$(find "$TARGET_DIR" -type f \( -name '*.js' -o -name '*.ts' -o -name '*.py' \) 2>/dev/null | head -n 1)
    [ -n "$f" ] && SCAN_DIR="$(dirname "$f")"
  fi
  if [ -z "$SCAN_DIR" ]; then
    skip "未找到脚本源码目录（可挂载 -v <目录>:/work/src 并设 SRC_DIR）"
  else
    echo "  [i] 扫描目录: $SCAN_DIR"
    if have semgrep; then
      SC_ARGS=()
      for p in javascript python; do
        if [ -f "$RULES_DIR/official/$p.yml" ]; then
          SC_ARGS+=(--config "$RULES_DIR/official/$p.yml")
        else
          SC_ARGS+=(--config "p/$p")
        fi
      done
      semgrep scan "${SC_ARGS[@]}" \
          --json --output "$OUT_DIR/07_script/semgrep_script.json" \
          --metrics=off --jobs "$JOBS" "$SCAN_DIR" \
          > "$LOGS/07_semgrep.log" 2>&1 \
        && ok "semgrep 脚本扫描完成" \
        || echo "  [warn] semgrep 脚本扫描失败，见 07_semgrep.log"
    else
      skip "semgrep 不可用"
    fi
    if have bandit; then
      # bandit 发现问题时退出码为 1，用输出文件是否存在来判断成功
      bandit -r "$SCAN_DIR" -f json -o "$OUT_DIR/07_script/bandit.json" \
          > "$LOGS/07_bandit.log" 2>&1
      if [ -s "$OUT_DIR/07_script/bandit.json" ]; then
        ok "bandit 完成"
      else
        echo "  [warn] bandit 失败，见 07_bandit.log"
      fi
    else
      skip "bandit 不可用"
    fi
    if have njsscan; then
      njsscan "$SCAN_DIR" --json > "$OUT_DIR/07_script/njsscan.json" \
          2> "$LOGS/07_njsscan.log"
      if [ -s "$OUT_DIR/07_script/njsscan.json" ]; then
        ok "njsscan 完成"
      else
        echo "  [warn] njsscan 失败，见 07_njsscan.log"
      fi
    else
      skip "njsscan 不可用"
    fi
    mark_done 7 "semgrep+bandit+njsscan"
  fi
fi

# ---------- 8. 汇总 ----------
banner "8/8" "汇总高风险点清单"
gate 8 "汇总"
rc=$?
if [ $rc -eq 0 ]; then
  if have python3; then
    python3 "$PIPELINE_HOME/scripts/summarize.py" "$OUT_DIR" \
      > "$LOGS/08_summary.log" 2>&1 \
      && ok "已生成 -> $OUT_DIR/高风险点清单.md" \
      || echo "  [!] 汇总失败，详见 $LOGS/08_summary.log"
    mark_done 8 "summarize.py"
  fi
fi

printf '\n===== 全部步骤结束 =====\n'
printf '结果目录: %s\n' "$OUT_DIR"
printf '先看这份: %s/高风险点清单.md\n' "$OUT_DIR"
printf '查看状态: %s/scripts/status.sh %s\n' "$PIPELINE_HOME" "$OUT_DIR"
