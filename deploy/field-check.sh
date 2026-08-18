#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# 测试机出发前 / 现场开打前自检。不连攻击，只确认文件、venv、配置、路由。
# 用法:  ./deploy/field-check.sh
# ------------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/real-amf/real-amf.env"

ok=0; bad=0
pass(){ echo "  OK  $*"; ok=$((ok+1)); }
fail(){ echo "  FAIL $*"; bad=$((bad+1)); }
warn(){ echo "  WARN $*"; }

echo "==== 文件 ===="
for f in "$REPO/config/huawei.json" "$HERE/ngt.sh" "$HERE/real-amf/run-gnb.sh" \
         "$HERE/real-amf/run-ue.sh" "$HERE/extract-ue-ids.sh" \
         "$HERE/操作手册_华为AMF.md"; do
  [[ -e "$f" ]] && pass "$(basename "$f")" || fail "缺 $f"
done
for f in "$HERE/ngt.sh" "$HERE/real-amf/run-gnb.sh" "$HERE/real-amf/run-ue.sh" \
         "$HERE/extract-ue-ids.sh" "$HERE/bootstrap.sh" \
         "$HERE/selftest-encode.sh" "$HERE/real-amf/capture-n2.sh" \
         "$HERE/real-amf/decode-n2.sh" "$HERE/real-amf/decode-n3.sh" \
         "$HERE/real-amf/observe.sh"; do
  [[ -x "$f" ]] || warn "$(basename "$f") 不可执行，跑: chmod +x deploy/*.sh deploy/real-amf/*.sh"
done

echo "==== 配置（必须是华为现场这组）===="
cd "$REPO"
python3 - <<PY
import json
c=json.load(open("config/huawei.json", encoding="utf-8"))
expect={"amf_addr":"14.66.2.5","mcc":"460","mnc":"08","sd":"010101","bind_ip":"13.254.241.142","gnb_id":4660}
bad=[]
for k,v in expect.items():
    if str(c.get(k))!=str(v):
        bad.append(f"  {k}={c.get(k)!r} 期望 {v!r}")
if bad:
    print("  FAIL huawei.json 与现场不符:")
    print("\n".join(bad))
    raise SystemExit(1)
print("  OK  huawei.json AMF/PLMN/bind_ip/gnb_id")
PY
[[ "${AMF_ADDR}" == "14.66.2.5" ]] && pass "real-amf.env AMF_ADDR" || fail "real-amf.env AMF_ADDR=$AMF_ADDR"
[[ "${UE1_IMSI}" == "460081111111113" ]] && pass "IMSI" || fail "IMSI=$UE1_IMSI"
[[ "${HOST_IP}" == "13.254.241.142" ]] && pass "HOST_IP" || fail "HOST_IP=$HOST_IP"
[[ "${MCC}${MNC}" == "46008" ]] && pass "PLMN 460/08" || fail "PLMN $MCC/$MNC"

echo "==== venv / 编码 ===="
if [[ -x "$REPO/.venv/bin/python" ]]; then
  pass "venv"
  if "$REPO/.venv/bin/python" "$REPO/validate_builders.py"; then
    pass "全部攻击报文能编码（validate_builders.py）"
  else
    fail "有报文编码失败，先看 validate_builders.py 输出，不要打那条"
  fi
  "$REPO/.venv/bin/python" -c "import sctp" 2>/dev/null && pass "pysctp 可 import" || warn "pysctp 不可 import（必须在 Linux 上跑 ngt.sh）"
else
  fail "没有 .venv，先 ./deploy/bootstrap.sh"
fi

echo "==== 系统 ===="
if [[ -e /proc/net/sctp ]] || grep -qw SCTP /proc/net/protocols 2>/dev/null; then
  pass "内核 SCTP"
else
  fail "内核无 SCTP"
fi
if ip -4 addr show | grep -q "13.254.241.142"; then
  pass "网卡上有 13.254.241.142"
else
  fail "本机没有 13.254.241.142（bind 会失败）"
fi
if ping -c 1 -W 2 14.66.2.5 >/dev/null 2>&1; then
  pass "ping 14.66.2.5"
else
  warn "ping 14.66.2.5 不通（有的网禁 ICMP，再看 sctp-ping）"
fi
command -v tshark >/dev/null && pass "tshark" || warn "无 tshark：sudo apt-get install -y tshark（抓包备用）"
UERANSIM_DIR="${UERANSIM_DIR:-$HOME/UERANSIM}"
[[ -x "$UERANSIM_DIR/build/nr-gnb" ]] && pass "nr-gnb" || fail "没有 $UERANSIM_DIR/build/nr-gnb"
[[ -x "$UERANSIM_DIR/build/nr-cli" ]] && pass "nr-cli" || warn "没有 nr-cli，读 AU 只能抓包"

echo "==== SCTP 关联（华为允许多条，UERANSIM 占着一条是正常的）===="
if [[ -r /proc/net/sctp/assocs ]]; then
  if grep -q 14.66.2.5 /proc/net/sctp/assocs 2>/dev/null; then
    pass "已有到 14.66.2.5 的 SCTP（合法 gNB 在跑，可同时开 ngap_tester）"
    grep 14.66.2.5 /proc/net/sctp/assocs || true
  else
    warn "当前没有到 AMF 的 SCTP（合法 gNB 可能还没起来）"
  fi
fi

echo
echo "结果: $ok 通过, $bad 失败"
[[ "$bad" -eq 0 ]] || exit 1
echo "下一步: 见 deploy/操作手册_华为AMF.md （黑盒观察 + 按编号一条一条打）"
