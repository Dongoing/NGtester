#!/bin/bash
# 5g-lab 脚本公共库：OS 检测 + 工具定位（被其它脚本 source，不单独运行）
# 目标：同一套脚本在 Windows(Git Bash + Docker Desktop) 和 Ubuntu(Docker Engine) 上都能用。

# ---- 宿主 OS ----
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) LAB_OS=windows ;;
  Linux*)               LAB_OS=linux ;;
  Darwin*)              LAB_OS=mac ;;
  *)                    LAB_OS=unknown ;;
esac

# ---- Docker 是否跑在 WSL2/Hyper-V 虚拟机里（决定要不要修时钟）----
# Windows 宿主的 Docker Desktop 用 WSL2 VM；从 WSL 发行版里直接跑也算。原生 Linux 不算。
LAB_NEED_CLOCKFIX=false
if [[ "$LAB_OS" == windows ]]; then
  LAB_NEED_CLOCKFIX=true
elif [[ "$LAB_OS" == linux && -r /proc/version ]] && grep -qi microsoft /proc/version 2>/dev/null; then
  LAB_NEED_CLOCKFIX=true
fi

# ---- 定位 kind / helm 等工具 ----
# 优先用 PATH 里的（Ubuntu 用户通常 apt/官方脚本装到 PATH），
# 找不到再退回项目 tools/ 下的二进制（Windows 自带 .exe；Linux 可放无后缀二进制）。
_lab_root() { echo "${LAB_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"; }
find_tool() {
  local name="$1"
  if command -v "$name" >/dev/null 2>&1; then command -v "$name"; return 0; fi
  local base; base="$(_lab_root)"
  local c
  for c in "$base/tools/$name" "$base/tools/$name.exe"; do
    [[ -f "$c" ]] && { echo "$c"; return 0; }
  done
  echo "$name"; return 1   # 兜底返回裸名，调用处会因找不到而报错
}

# 供脚本快速拿到 kind/helm 路径
KIND_BIN="$(find_tool kind)"
HELM_BIN="$(find_tool helm)"
