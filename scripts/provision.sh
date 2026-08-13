#!/bin/bash
# 5g-lab 订阅数据预置脚本
# 用法: ./scripts/provision.sh <open5gs|free5gc>
#   (oai 的订阅在 mysql 初始化 SQL 里；sdcore 的订阅在 helm values 里，均无需单独预置)

set -e
LAB_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CORE="$1"

case "$CORE" in
  open5gs)
    # 统一测试 UE ×10: IMSI 001010000000001..010, 同 K/OPc, MSISDN 0900000001..010, 切片 sst=1 sd=010203
    MONGO=$(grep -E "^MONGO_IP=" "$LAB_ROOT/cores/open5gs/.env" | cut -d= -f2)
    for n in $(seq 1 ${NUM_UE:-10}); do
      IMSI=$(printf "0010100000000%02d" "$n")
      MSISDN=$(printf "09000000%02d" "$n")
      docker exec o5gs-webui bash -c "export DB_URI=mongodb://$MONGO/open5gs; \
        /open5gs/misc/db/open5gs-dbctl add $IMSI \
        8baf473f2f8fd09487cccbd7097c6862 8e27b6af0e692e750f32667a3b14605d" >/dev/null 2>&1 || true
      docker exec o5gs-webui mongosh --quiet mongodb://$MONGO/open5gs --eval \
        "db.subscribers.updateOne({imsi:\"$IMSI\"},{\$set:{\"security.opc\":\"8e27b6af0e692e750f32667a3b14605d\",\"security.op\":null,\"slice.0.sst\":1,\"slice.0.sd\":\"010203\",\"msisdn\":[\"$MSISDN\"]}})" >/dev/null
    done
    echo ">> Open5GS 已预置 ${NUM_UE:-10} 个订阅 (IMSI 001010000000001..$(printf '%02d' ${NUM_UE:-10}), MSISDN 0900000001..)"
    ;;
  free5gc)
    TOKEN=$(curl -s -X POST http://localhost:5000/api/login \
      -H "Content-Type: application/json" \
      -d '{"username":"admin","password":"free5gc"}' | grep -oE '"access_token":"[^"]+"' | cut -d'"' -f4)
    TPL="$LAB_ROOT/cores/free5gc/subscriber.json"
    for n in $(seq 1 ${NUM_UE:-10}); do
      IMSI=$(printf "0010100000000%02d" "$n")
      MSISDN=$(printf "09000000%02d" "$n")
      # 从模板替换 IMSI 与 gpsis(MSISDN)，K/OPc/切片/PLMN 保持统一值不变
      BODY=$(sed -e "s/imsi-001010000000001/imsi-$IMSI/g" \
                 -e "s/\"001010000000001\"/\"$IMSI\"/g" \
                 -e "s/msisdn-0900000000/msisdn-$MSISDN/g" "$TPL")
      code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "http://localhost:5000/api/subscriber/imsi-$IMSI/00101" \
        -H "Content-Type: application/json" -H "Token: $TOKEN" -d "$BODY")
      echo "   IMSI $IMSI MSISDN $MSISDN -> HTTP $code"
    done
    echo ">> free5GC 已预置 ${NUM_UE:-10} 个订阅 (IMSI 001010000000001..)"
    ;;
  *)
    echo "用法: $0 {open5gs|free5gc}"; exit 1 ;;
esac
