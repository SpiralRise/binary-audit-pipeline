#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
无源码二进制静态审计流水线 —— 宿主机一键封装脚本

用法:
    python3 audit.py <输入目录> [输出目录] [选项]

示例:
    sudo python3 audit.py /data/firmware
    sudo python3 audit.py /data/firmware /data/out
    sudo python3 audit.py /data/firmware /data/out --cve --jobs 4
    sudo python3 audit.py /data/firmware /data/out --only 8      # 只重跑第8步汇总
    sudo python3 audit.py /data/firmware /data/out --force       # 强制全部重跑
    python3 audit.py /data/firmware /data/out --shell            # 只打印 docker 命令

默认行为:
    - 默认开启 Joern 污点分析（第6步）
    - 默认关闭 CVE 扫描（第1步）
    - 默认 GHIDRA_SCOPE=hits（只反编译 capa/CWE 命中的文件）
    - 默认挂载 <PIPELINE_DIR>/scripts 到容器内，改脚本后无需重建镜像
    - 输出目录不指定时：<输入目录名>-out（放在输入目录同级）
"""
import argparse
import os
import shlex
import subprocess
import sys
import time
from datetime import datetime

IMAGE = os.environ.get("IMAGE", "ghcr.io/spiralrise/binary-audit-pipeline:1.1.0")
PIPELINE_DIR = os.environ.get(
    "PIPELINE_DIR", os.path.dirname(os.path.abspath(__file__))
)
LOCAL_SCRIPTS = os.path.join(PIPELINE_DIR, "scripts")


def run(cmd):
    print("+ " + " ".join(shlex.quote(c) for c in cmd), flush=True)
    return subprocess.call(cmd)


def main():
    ap = argparse.ArgumentParser(
        description="无源码二进制静态审计流水线（默认开 Joern，默认关 CVE）",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("target", help="待分析目录（递归扫描）")
    ap.add_argument("out", nargs="?", default=None, help="输出目录（默认 <目标名>-out）")
    ap.add_argument("--cve", action="store_true", help="开启第1步 CVE 扫描（默认关）")
    ap.add_argument("--no-joern", action="store_true", help="关闭第6步 Joern 污点分析（默认开）")
    ap.add_argument("--all-files", action="store_true", help="Ghidra 反编译全部文件（默认只反编译命中文件）")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 4, help="并行度")
    ap.add_argument("--only", default="", help="只跑指定步骤，如 8 或 6,8")
    ap.add_argument("--start", default="0", help="从第几步开始")
    ap.add_argument("--force", action="store_true", help="强制重跑（清理对应输出）")
    ap.add_argument("--no-resume", action="store_true", help="关闭断点续跑")
    ap.add_argument("--no-local-scripts", action="store_true",
                    help="不挂载宿主机 scripts（改用镜像内置脚本）")
    ap.add_argument("--name", default="", help="容器名（默认自动生成；退出后不删除）")
    ap.add_argument("--build", action="store_true", help="运行前先重建镜像")
    ap.add_argument("--shell", action="store_true", help="只打印将执行的 docker 命令，不执行")
    args = ap.parse_args()

    target = os.path.abspath(args.target)
    if not os.path.isdir(target):
        sys.exit("[!] 输入目录不存在: %s" % target)

    if args.out:
        out = os.path.abspath(args.out)
    else:
        out = os.path.abspath(target.rstrip("/\\") + "-out")
    os.makedirs(out, exist_ok=True)

    if args.build:
        if run(["docker", "build", "-t", IMAGE, PIPELINE_DIR]) != 0:
            sys.exit("[!] 镜像构建失败")

    # 当前用户不在 docker 组、又无法免密 sudo 时提前给出提示，避免跑到一半才报错
    if not args.shell and hasattr(os, "geteuid") and os.geteuid() != 0:
        try:
            subprocess.run(["sudo", "-n", "true"], timeout=5,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=False)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            sys.exit("[!] sudo 无响应或不可用。请确认当前用户已加入 docker 组，"
                     "或用 root 身份直接运行本脚本")

    if not args.shell and run(["docker", "image", "inspect", IMAGE]) != 0:
        sys.exit("[!] 镜像不存在: %s\n    先拉取: sudo docker pull %s\n"
                 "    或构建: sudo docker build -t %s %s"
                 % (IMAGE, IMAGE, IMAGE, PIPELINE_DIR))

    env = {
        "JOBS": str(args.jobs),
        "WITH_CVEBIN": "1" if args.cve else "0",
        "WITH_CAPA": "1",
        "WITH_CWE": "1",
        "WITH_GHIDRA": "1",
        "WITH_JOERN": "0" if args.no_joern else "1",
        "GHIDRA_SCOPE": "all" if args.all_files else "hits",
        "RESUME": "0" if args.no_resume else "1",
        "FORCE": "1" if args.force else "0",
        "ONLY_STEP": args.only,
        "START_STEP": args.start,
    }

    if args.name:
        cmd = ["docker", "run", "--name", args.name]
    else:
        cmd = ["docker", "run", "--rm"]

    cmd += [
        "-v", "%s:/work/targets:ro" % target,
        "-v", "%s:/work/out" % out,
    ]

    use_local_scripts = (not args.no_local_scripts) and os.path.isfile(
        os.path.join(LOCAL_SCRIPTS, "pipeline.sh"))
    if use_local_scripts:
        cmd += ["-v", "%s:/opt/pipeline/scripts:ro" % LOCAL_SCRIPTS]

    for k, v in env.items():
        cmd += ["-e", "%s=%s" % (k, v)]
    cmd += [IMAGE, "pipeline"]

    print("=" * 70)
    print("输入目录 : %s" % target)
    print("输出目录 : %s" % out)
    print("CVE 扫描 : %s" % ("开" if args.cve else "关"))
    print("Joern    : %s" % ("关" if args.no_joern else "开"))
    print("反编译   : %s" % ("全部文件" if args.all_files else "只反编译 capa/CWE 命中的文件"))
    print("脚本来源 : %s" % ("宿主机 " + LOCAL_SCRIPTS if use_local_scripts else "镜像内置"))
    print("=" * 70)

    if args.shell:
        print(" ".join(shlex.quote(c) for c in cmd))
        return

    t0 = time.time()
    rc = run(cmd)
    dt = time.time() - t0
    print("=" * 70)
    print("耗时: %d 分 %d 秒   退出码: %d" % (dt // 60, dt % 60, rc))
    print("汇总清单: %s/高风险点清单.md" % out)
    print("步骤状态: sudo docker run --rm -v %s:/work/out %s sh /opt/pipeline/scripts/status.sh /work/out"
          % (out, IMAGE))
    sys.exit(rc)


if __name__ == "__main__":
    main()
