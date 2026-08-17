#!/usr/bin/env bash
# ==============================================================================
# 测试机一键环境准备。原生 Ubuntu 或 WSL2 都可以。
#
# 做完这些后，就能原生(不经 Docker Desktop)直连真实华为 AMF 的 SCTP：
#   - 编译 UERANSIM（合法 gNB + UE，用于造一个已注册的受害 UE）
#   - 建 ngap_tester 的 Python venv（流氓 gNB，发攻击）
#
# 用法:
#   cd ngap_tester
#   ./deploy/bootstrap.sh
# ==============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"       # .../ngap_tester/deploy
REPO="$(cd "$HERE/.." && pwd)"              # .../ngap_tester
UERANSIM_DIR="${UERANSIM_DIR:-$HOME/UERANSIM}"

c_info(){ printf '\n\033[1;36m[bootstrap] %s\033[0m\n' "$*"; }
c_warn(){ printf '\033[1;33m[warn] %s\033[0m\n' "$*"; }
c_die(){  printf '\033[1;31m[FATAL] %s\033[0m\n' "$*" >&2; exit 1; }

# ---- 0. 环境 sanity ----
if grep -qi microsoft /proc/version 2>/dev/null; then
  c_warn "检测到 WSL。连外部 AMF 需要镜像网络；原生 Ubuntu 可忽略。"
fi
chmod +x "$HERE"/*.sh "$HERE/real-amf"/*.sh 2>/dev/null || true

# ---- 1. 内核 SCTP 支持（成败关键，NGAP 全靠它）----
c_info "检查内核 SCTP 支持 ..."
if [[ -e /proc/net/sctp ]] || grep -qw SCTP /proc/net/protocols 2>/dev/null; then
  echo "  OK: 内核支持 SCTP"
else
  c_die "内核不支持 SCTP。请在 Windows(管理员 PowerShell)跑 'wsl --update' 升级到较新的
        WSL2 内核(6.6.x 自带 SCTP)，再 'wsl --shutdown' 后重试本脚本。"
fi

# ---- 2. 系统依赖 ----
c_info "安装系统依赖 (build 工具 / libsctp / python venv) ..."
sudo apt-get update
sudo apt-get install -y \
  build-essential make gcc g++ cmake git iproute2 iputils-ping \
  libsctp-dev lksctp-tools tshark \
  python3 python3-venv python3-pip

# ---- 3. 编译 UERANSIM（合法 gNB + UE）----
if [[ -x "$UERANSIM_DIR/build/nr-gnb" && -x "$UERANSIM_DIR/build/nr-ue" ]]; then
  c_info "UERANSIM 已构建，跳过 ($UERANSIM_DIR)"
else
  c_info "编译 UERANSIM -> $UERANSIM_DIR (首次约 3-5 分钟) ..."
  [[ -d "$UERANSIM_DIR/.git" ]] || git clone https://github.com/aligungr/UERANSIM "$UERANSIM_DIR"
  make -C "$UERANSIM_DIR"
fi
[[ -x "$UERANSIM_DIR/build/nr-gnb" ]] || c_die "UERANSIM 编译失败：缺 $UERANSIM_DIR/build/nr-gnb"

# ---- 4. ngap_tester Python venv（流氓 gNB）----
c_info "创建 ngap_tester 的 Python venv 并装依赖 (pycrate/pysctp) ..."
python3 -m venv "$REPO/.venv"
"$REPO/.venv/bin/pip" install --upgrade pip >/dev/null
"$REPO/.venv/bin/pip" install -r "$REPO/requirements.txt"

# ---- 5. 完成 + 下一步 ----
c_info "完成 ✅  下一步（现场参数已写入 env / huawei.json）："
cat <<EOF
  现场只看 deploy/操作手册_华为AMF.md 第一节。出发前先 ./deploy/field-check.sh
  1) ./deploy/field-check.sh
  2) ./deploy/real-amf/run-gnb.sh    和    ./deploy/real-amf/run-ue.sh
  3) ./deploy/extract-ue-ids.sh      # 读本次随机 AU（不要 sweep）
  4) ./deploy/ngt.sh sctp-ping && ./deploy/ngt.sh ng-setup
  5) ./deploy/ngt.sh path-switch --source-amf-ue-id <本次AU>
EOF
