#!/bin/bash
# 端到端 demo：起 REST server，用 curl 调完整流程
# init → store → share → accept → append → revoke → 验证前向保密

set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PORT=18080
BASE="http://127.0.0.1:$PORT/api"

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "=== 启动 REST server (port $PORT) ==="
PORT=$PORT go run ./cmd/cs161-server > /tmp/cs161-demo.log 2>&1 &
SERVER_PID=$!

# 等待 server 就绪
for i in $(seq 1 30); do
    if curl -s -o /dev/null -w "%{http_code}" "$BASE/users/init" -X POST -d '{}' 2>/dev/null | grep -qE "400|200"; then
        break
    fi
    sleep 0.5
done

echo ""
echo "=== 1. 初始化两个用户 ==="
curl -s -X POST "$BASE/users/init" -d '{"username":"alice","password":"pwd123"}'
echo ""
curl -s -X POST "$BASE/users/init" -d '{"username":"bob","password":"pwd123"}'
echo ""

echo ""
echo "=== 2. Alice 换取 token ==="
ALICE_TOKEN=$(curl -s -X POST "$BASE/auth/token" -d '{"username":"alice","password":"pwd123"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
echo "alice token: ${ALICE_TOKEN:0:16}..."

echo ""
echo "=== 3. Alice 存储文件 ==="
curl -s -X POST "$BASE/files/store" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -d '{"username":"alice","password":"pwd123","filename":"secret.txt","data":"initial content"}'
echo ""

echo ""
echo "=== 4. Alice 加载验证 ==="
curl -s "$BASE/files/load?username=alice&password=pwd123&filename=secret.txt" \
    -H "Authorization: Bearer $ALICE_TOKEN"
echo ""

echo ""
echo "=== 5. Alice 创建共享邀请给 Bob ==="
INV_ID=$(curl -s -X POST "$BASE/share/invite" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -d '{"username":"alice","password":"pwd123","filename":"secret.txt","recipient":"bob"}' \
    | python3 -c "import sys,json;print(json.load(sys.stdin)['invitation_id'])")
echo "invitation id: $INV_ID"

echo ""
echo "=== 6. Bob 换 token 并接受邀请 ==="
BOB_TOKEN=$(curl -s -X POST "$BASE/auth/token" -d '{"username":"bob","password":"pwd123"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
curl -s -X POST "$BASE/share/accept" \
    -H "Authorization: Bearer $BOB_TOKEN" \
    -d "{\"username\":\"bob\",\"password\":\"pwd123\",\"sender\":\"alice\",\"filename\":\"secret.txt\",\"invitation_id\":\"$INV_ID\"}"
echo ""

echo ""
echo "=== 7. Bob 加载共享文件 ==="
curl -s "$BASE/files/load?username=bob&password=pwd123&filename=secret.txt" \
    -H "Authorization: Bearer $BOB_TOKEN"
echo ""

echo ""
echo "=== 8. Bob 追加内容（stepVersion 乐观锁保护）==="
curl -s -X POST "$BASE/files/append" \
    -H "Authorization: Bearer $BOB_TOKEN" \
    -d '{"username":"bob","password":"pwd123","filename":"secret.txt","data":" bob appended"}'
echo ""

echo ""
echo "=== 9. Alice 加载看到 Bob 的追加 ==="
curl -s "$BASE/files/load?username=alice&password=pwd123&filename=secret.txt" \
    -H "Authorization: Bearer $ALICE_TOKEN"
echo ""

echo ""
echo "=== 10. Alice 撤销 Bob（BFS + 全密钥重生 + 通知）==="
curl -s -X POST "$BASE/share/revoke" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -d '{"username":"alice","password":"pwd123","filename":"secret.txt","recipient":"bob"}'
echo ""

echo ""
echo "=== 11. Alice 追加新内容（用新密钥）==="
curl -s -X POST "$BASE/files/append" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -d '{"username":"alice","password":"pwd123","filename":"secret.txt","data":" post-revoke"}'
echo ""

echo ""
echo "=== 12. 验证 Bob 无法再加载（前向保密）==="
set +e
BOB_LOAD=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/files/load?username=bob&password=pwd123&filename=secret.txt" \
    -H "Authorization: Bearer $BOB_TOKEN")
set -e
if [ "$BOB_LOAD" != "200" ]; then
    echo "✅ Bob 被撤销后无法访问（HTTP $BOB_LOAD，前向保密生效）"
else
    echo "❌ FAIL: Bob 仍能访问被撤销的文件"
    exit 1
fi

echo ""
echo "=== 13. 查 Bob 的通知 ==="
curl -s "$BASE/notifications?recipient=bob" -H "Authorization: Bearer $BOB_TOKEN"
echo ""

echo ""
echo "=== 14. 查审计日志 ==="
curl -s "$BASE/audit?subject=alice" -H "Authorization: Bearer $ALICE_TOKEN" | python3 -c "import sys,json;d=json.load(sys.stdin);print(f'count={d[\"count\"]}')"

echo ""
echo "=== 15. Alice 加载最终文件 ==="
curl -s "$BASE/files/load?username=alice&password=pwd123&filename=secret.txt" \
    -H "Authorization: Bearer $ALICE_TOKEN"
echo ""

echo ""
echo "=== Demo 完成 ==="
echo ""
echo "要点："
echo "  - 文件分块 + AES 加密 + HMAC 完整性"
echo "  - invitation 共享（RSA + 数字签名）"
echo "  - stepVersion 乐观锁保护并发追加"
echo "  - RevokeAccess BFS + 全密钥重生（前向保密）"
echo "  - Bearer 鉴权 + 令牌桶限流 + 审计日志 + 通知"
echo ""
echo "详见："
echo "  docs/benchmark.md      并发基准数据"
echo "  docs/threat-model.md   威胁模型与防御"
