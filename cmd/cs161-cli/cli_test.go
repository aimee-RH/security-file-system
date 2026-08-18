package main

import (
	"bytes"
	"strings"
	"testing"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

// 接缝 1：CLI 入口能成功执行 user init 命令
func TestCLIUserInitSuccess(t *testing.T) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()

	out, err := executeCommand("user", "init", "--username", "alice", "--password", "pwd123")
	if err != nil {
		t.Fatalf("expected nil error, got %v; out=%s", err, out)
	}
	if !strings.Contains(out, "alice") {
		t.Errorf("expected output to contain username 'alice', got: %s", out)
	}
}

// 接缝 1：重复 user init 应失败
func TestCLIUserInitDuplicate(t *testing.T) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()

	_, _ = executeCommand("user", "init", "--username", "alice", "--password", "pwd123")
	out, err := executeCommand("user", "init", "--username", "alice", "--password", "pwd123")
	if err == nil {
		t.Errorf("expected duplicate user init to fail, but it succeeded; out=%s", out)
	}
}

// 接缝 2：file store 命令路由参数到 client.StoreFile
func TestCLIFileStoreAndLoad(t *testing.T) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()

	// init user
	if _, err := executeCommand("user", "init", "--username", "alice", "--password", "pwd123"); err != nil {
		t.Fatalf("user init failed: %v", err)
	}

	// store file
	out, err := executeCommand("file", "store", "--username", "alice", "--password", "pwd123",
		"--filename", "test.txt", "--data", "hello world")
	if err != nil {
		t.Fatalf("file store failed: %v; out=%s", err, out)
	}

	// load file
	out, err = executeCommand("file", "load", "--username", "alice", "--password", "pwd123",
		"--filename", "test.txt")
	if err != nil {
		t.Fatalf("file load failed: %v; out=%s", err, out)
	}
	if !strings.Contains(out, "hello world") {
		t.Errorf("expected load output to contain 'hello world', got: %s", out)
	}
}

// 接缝 2：file append 命令追加数据
func TestCLIFileAppend(t *testing.T) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()

	_, _ = executeCommand("user", "init", "--username", "alice", "--password", "pwd123")
	_, _ = executeCommand("file", "store", "--username", "alice", "--password", "pwd123",
		"--filename", "test.txt", "--data", "hello")

	out, err := executeCommand("file", "append", "--username", "alice", "--password", "pwd123",
		"--filename", "test.txt", "--data", " world")
	if err != nil {
		t.Fatalf("file append failed: %v; out=%s", err, out)
	}

	// load 验证内容包含追加数据
	out, err = executeCommand("file", "load", "--username", "alice", "--password", "pwd123",
		"--filename", "test.txt")
	if err != nil {
		t.Fatalf("file load failed: %v", err)
	}
	if !strings.Contains(out, "hello world") {
		t.Errorf("expected 'hello world' after append, got: %s", out)
	}
}

// 接缝 3：未知命令应返回非零 exit code
func TestCLIUnknownCommand(t *testing.T) {
	_, err := executeCommand("nonexistent-command")
	if err == nil {
		t.Errorf("expected unknown command to fail")
	}
}

// 接缝 3：缺参数应返回错误
func TestCLIMissingFlag(t *testing.T) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()

	_, err := executeCommand("user", "init", "--username", "alice") // 缺 --password
	if err == nil {
		t.Errorf("expected missing --password to fail")
	}
}

// executeCommand 是 cobra 测试 helper：注入 args，捕获 stdout
// 借鉴 cobra 官方文档的 root command 测试模式
func executeCommand(args ...string) (string, error) {
	buf := new(bytes.Buffer)
	root := newRootCmd()
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

// TestCLIIntegrationWithClientPackage 验证 CLI 与 client 包集成正确
// 通过 CLI 创建用户后，直接用 client.GetUser 也能取回
func TestCLIIntegrationWithClientPackage(t *testing.T) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()

	if _, err := executeCommand("user", "init", "--username", "alice", "--password", "pwd123"); err != nil {
		t.Fatalf("CLI user init failed: %v", err)
	}

	// 直接通过 client 包验证
	u, err := client.GetUser("alice", "pwd123")
	if err != nil {
		t.Fatalf("client.GetUser failed after CLI init: %v", err)
	}
	if u.Username != "alice" {
		t.Errorf("expected username 'alice', got %s", u.Username)
	}
}
