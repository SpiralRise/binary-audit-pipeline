#!/usr/bin/env bash
# 容器入口：默认直接跑流水线；传 shell 进入交互式排查
set -euo pipefail

case "${1:-pipeline}" in
  pipeline)
    exec /opt/pipeline/scripts/pipeline.sh
    ;;
  shell|bash)
    exec /bin/bash
    ;;
  *)
    exec "$@"
    ;;
esac
