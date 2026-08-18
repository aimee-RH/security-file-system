package client

// 故事 3：端到端 demo 测试
// 验证完整业务流程作为 Go 测试，确保 demo.sh 背后的逻辑可靠
// scripts/demo.sh 是 CLI 包装层，本测试覆盖底层 client 包流程

import (
	"testing"

	userlib "github.com/cs161-staff/project2-userlib"
)

func TestEndToEndDemo(t *testing.T) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	ClearNotificationsForTest()

	// 1. 初始化两个用户
	alice, err := InitUser("alice", "pwd123")
	if err != nil {
		t.Fatalf("init alice: %v", err)
	}
	bob, err := InitUser("bob", "pwd123")
	if err != nil {
		t.Fatalf("init bob: %v", err)
	}

	// 2. Alice 存储文件
	if err := alice.StoreFile("secret.txt", []byte("initial content")); err != nil {
		t.Fatalf("store: %v", err)
	}

	// 3. Alice 加载验证
	data, err := alice.LoadFile("secret.txt")
	if err != nil || string(data) != "initial content" {
		t.Fatalf("load after store: %v, data=%s", err, string(data))
	}

	// 4. Alice 创建共享邀请
	invID, err := alice.CreateInvitation("secret.txt", "bob")
	if err != nil {
		t.Fatalf("invite: %v", err)
	}

	// 5. Bob 接受
	if err := bob.AcceptInvitation("alice", invID, "secret.txt"); err != nil {
		t.Fatalf("accept: %v", err)
	}

	// 6. Bob 加载共享文件
	data, err = bob.LoadFile("secret.txt")
	if err != nil || string(data) != "initial content" {
		t.Fatalf("bob load: %v, data=%s", err, string(data))
	}

	// 7. Bob 追加（触发 stepVersion）
	if err := bob.AppendWithRetry("secret.txt", []byte(" bob appended"), 3); err != nil {
		t.Fatalf("bob append: %v", err)
	}

	// 8. Alice 加载看到 Bob 的追加
	data, err = alice.LoadFile("secret.txt")
	if err != nil {
		t.Fatalf("alice load after bob append: %v", err)
	}
	if string(data) != "initial content bob appended" {
		t.Errorf("expected 'initial content bob appended', got %q", string(data))
	}

	// 9. Alice 撤销 Bob（BFS + 全密钥重生 + 通知）
	NotifyHook = func(recipient, event, payload string) {
		// 通知会进 NotifyStore（cmd/cs161-server），这里只验证 hook 被调
		t.Logf("Notify: %s → %s (%s)", recipient, event, payload)
	}
	defer func() { NotifyHook = nil }()

	if err := alice.RevokeAccess("secret.txt", "bob"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// 10. Alice 追加新内容（用新密钥）
	if err := alice.AppendWithRetry("secret.txt", []byte(" post-revoke"), 3); err != nil {
		t.Fatalf("alice append post-revoke: %v", err)
	}

	// 11. Bob 无法再加载（前向保密）
	_, err = bob.LoadFile("secret.txt")
	if err == nil {
		t.Error("FAIL: bob should not load after revoke (forward secrecy broken)")
	} else {
		t.Logf("✅ Bob 被撤销后无法访问（%v）", err)
	}

	// 12. Alice 加载最终文件
	data, err = alice.LoadFile("secret.txt")
	if err != nil {
		t.Fatalf("alice final load: %v", err)
	}
	expected := "initial content bob appended post-revoke"
	if string(data) != expected {
		t.Errorf("expected %q, got %q", expected, string(data))
	}

	t.Log("=== End-to-end demo PASS ===")
}

// ClearNotificationsForTest 重置通知 hook（避免污染其他测试）
func ClearNotificationsForTest() {
	NotifyHook = nil
}
