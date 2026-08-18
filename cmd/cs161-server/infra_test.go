package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cs161-staff/project2-starter-code/client"
	"github.com/gin-gonic/gin"
	userlib "github.com/cs161-staff/project2-userlib"
)

// B07 审计日志测试

func TestLogAuditAndQuery(t *testing.T) {
	ClearAuditLog()
	LogAudit(Identity{Type: "user", Subject: "alice"}, "store", "test.txt", "success", 200, "POST", "/api/files/store")
	LogAudit(Identity{Type: "agent", Subject: "agent-001"}, "load", "test.txt", "success", 200, "GET", "/api/files/load")

	// 查全部
	all := GetAuditLog("")
	if len(all) != 2 {
		t.Errorf("expected 2 entries, got %d", len(all))
	}

	// 按 subject 查
	alice := GetAuditLog("alice")
	if len(alice) != 1 {
		t.Errorf("expected 1 entry for alice, got %d", len(alice))
	}
	if alice[0].Action != "store" {
		t.Errorf("expected action=store, got %s", alice[0].Action)
	}
}

func TestAuditMiddlewareRecords(t *testing.T) {
	ClearAuditLog()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(AuditMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	entries := GetAuditLog("")
	if len(entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(entries))
	}
	if entries[0].Path != "/test" {
		t.Errorf("expected path=/test, got %s", entries[0].Path)
	}
}

func TestAuditMiddlewareFailRecord(t *testing.T) {
	ClearAuditLog()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(AuditMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(500, gin.H{"error": "fail"}) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	entries := GetAuditLog("")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Result != "fail" {
		t.Errorf("expected result=fail, got %s", entries[0].Result)
	}
	if entries[0].StatusCode != 500 {
		t.Errorf("expected status=500, got %d", entries[0].StatusCode)
	}
}

// B08 频次限制测试

func TestRateLimiterAllow(t *testing.T) {
	limiter := NewRateLimiter(3, time.Second, 3) // 桶容量 3，每秒补充 3

	if !limiter.Allow("alice") {
		t.Error("first request should be allowed")
	}
	if !limiter.Allow("alice") {
		t.Error("second request should be allowed")
	}
	if !limiter.Allow("alice") {
		t.Error("third request should be allowed")
	}
	if limiter.Allow("alice") {
		t.Error("fourth request should be rate-limited")
	}
}

func TestRateLimiterDifferentKeys(t *testing.T) {
	limiter := NewRateLimiter(1, time.Second, 1)
	if !limiter.Allow("alice") {
		t.Error("alice first request should be allowed")
	}
	if !limiter.Allow("bob") {
		t.Error("bob first request should be allowed (different bucket)")
	}
	if limiter.Allow("alice") {
		t.Error("alice second request should be rate-limited")
	}
}

func TestRateLimitMiddleware429(t *testing.T) {
	TokenStore.Lock()
	TokenStore.m = make(map[string]Identity)
	TokenStore.Unlock()

	token, _ := IssueToken(Identity{Type: "user", Subject: "alice"})
	limiter := NewRateLimiter(1, time.Second, 1)

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(AuthMiddleware(), RateLimitMiddleware(limiter))
	r.GET("/test", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

	// 第一次允许
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("first request should succeed, got %d", w.Code)
	}

	// 第二次 429
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("second request should be 429, got %d", w.Code)
	}
}

// B09 通知服务测试

func TestNotifyAndRetrieve(t *testing.T) {
	ClearNotifications()
	Notify("bob", "revoked", "file=test.txt")
	Notify("bob", "shared", "file=test.txt,sender=alice")

	notifs := GetNotifications("bob")
	if len(notifs) != 2 {
		t.Fatalf("expected 2 notifications, got %d", len(notifs))
	}
	if notifs[0].Event != "revoked" {
		t.Errorf("expected first event=revoked, got %s", notifs[0].Event)
	}
}

func TestNotifyDifferentRecipients(t *testing.T) {
	ClearNotifications()
	Notify("bob", "revoked", "f1")
	Notify("charlie", "shared", "f2")

	if len(GetNotifications("bob")) != 1 {
		t.Error("bob should have 1 notification")
	}
	if len(GetNotifications("charlie")) != 1 {
		t.Error("charlie should have 1 notification")
	}
}

// 集成测试：B06 鉴权 + B07 审计 + B08 限流 + B09 通知 串联
func TestIntegratedMiddleware(t *testing.T) {
	TokenStore.Lock()
	TokenStore.m = make(map[string]Identity)
	TokenStore.Unlock()
	ClearAuditLog()
	ClearNotifications()

	token, _ := IssueToken(Identity{Type: "user", Subject: "alice"})
	limiter := NewRateLimiter(10, time.Second, 10)

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(AuthMiddleware(), AuditMiddleware(), RateLimitMiddleware(limiter))
	r.GET("/test", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 审计日志应记录这次请求
	entries := GetAuditLog("alice")
	if len(entries) != 1 {
		t.Errorf("expected 1 audit entry for alice, got %d", len(entries))
	}
}

// 并发安全测试：多 goroutine 同时 LogAudit 不丢日志
func TestConcurrentLogAudit(t *testing.T) {
	ClearAuditLog()
	var wg sync.WaitGroup
	n := 100
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			LogAudit(Identity{Type: "user", Subject: "alice"}, "test", "t", "success", 200, "GET", "/test")
		}()
	}
	wg.Wait()

	entries := GetAuditLog("")
	if len(entries) != n {
		t.Errorf("expected %d entries, got %d", n, len(entries))
	}
}

// 接入层验收测试：生产路由 newAuthenticatedRouter 挂全部 middleware

// 验收 1：无 token 访问受保护 endpoint 返回 401
func TestAuthenticatedRouterRejectsNoToken(t *testing.T) {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/files/store", nil)
	newAuthenticatedRouter().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", w.Code)
	}
}

// 验收 2：/api/auth/token 正确凭证换 token，错误凭证 401
func TestIssueToken(t *testing.T) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	client.InitUser("alice", "pwd123")

	body := `{"username":"alice","password":"pwd123"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/auth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	newAuthenticatedRouter().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d; body=%s", w.Code, w.Body.String())
	}

	// 错误密码 401
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/api/auth/token", strings.NewReader(`{"username":"alice","password":"wrong"}`))
	req.Header.Set("Content-Type", "application/json")
	newAuthenticatedRouter().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for bad password, got %d", w.Code)
	}
}

// 验收 3：持 token 访问受保护 endpoint 通过
func TestAuthenticatedRouterAllowsWithToken(t *testing.T) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	TokenStore.Lock()
	TokenStore.m = make(map[string]Identity)
	TokenStore.Unlock()

	client.InitUser("alice", "pwd123")

	// 换 token
	body := `{"username":"alice","password":"pwd123"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/auth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	newAuthenticatedRouter().ServeHTTP(w, req)
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	token, ok := resp["token"]
	if !ok {
		t.Fatalf("no token in response: %s", w.Body.String())
	}

	// 用 token 存文件
	storeBody := `{"username":"alice","password":"pwd123","filename":"f.txt","data":"hi"}`
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/api/files/store", strings.NewReader(storeBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	newAuthenticatedRouter().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("expected 200 with token, got %d; body=%s", w.Code, w.Body.String())
	}
}

// 验收 4：/api/audit 查询审计日志（需要 token）
func TestAuditEndpoint(t *testing.T) {
	ClearAuditLog()
	TokenStore.Lock()
	TokenStore.m = make(map[string]Identity)
	TokenStore.Unlock()
	token, _ := IssueToken(Identity{Type: "user", Subject: "alice"})

	// 触发一次受保护请求产生审计日志
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/files/store", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+token)
	newAuthenticatedRouter().ServeHTTP(w, req)

	// 查 audit
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/api/audit?subject=alice", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	newAuthenticatedRouter().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "alice") {
		t.Errorf("expected body to contain alice, got %s", w.Body.String())
	}
}

// 验收 5：RevokeAccess 触发通知（client.NotifyHook 注入后）
func TestRevokeTriggersNotify(t *testing.T) {
	ClearNotifications()
	prevHook := client.NotifyHook
	client.NotifyHook = Notify
	defer func() { client.NotifyHook = prevHook }()

	userlib.DatastoreClear()
	userlib.KeystoreClear()
	client.InitUser("alice", "pwd123")
	client.InitUser("bob", "pwd123")

	u, _ := client.GetUser("alice", "pwd123")
	u.StoreFile("secret.txt", []byte("content"))
	invID, _ := u.CreateInvitation("secret.txt", "bob")

	bob, _ := client.GetUser("bob", "pwd123")
	bob.AcceptInvitation("alice", invID, "secret.txt")

	if err := u.RevokeAccess("secret.txt", "bob"); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}

	notifs := GetNotifications("bob")
	if len(notifs) == 0 {
		t.Fatalf("expected bob to receive notification, got 0")
	}
	found := false
	for _, n := range notifs {
		if n.Event == "access_revoked" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected access_revoked event, got %v", notifs)
	}
}

// 验收 6：stepVersion 并发安全——多个 goroutine 同时 append 同一文件
// 都应成功（不会覆盖），不会出现 chunk 丢失
func TestStepVersionConcurrentAppend(t *testing.T) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	client.InitUser("alice", "pwd123")

	u, _ := client.GetUser("alice", "pwd123")
	u.StoreFile("concurrent.txt", []byte("init"))

	var wg sync.WaitGroup
	n := 10
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			u.AppendWithRetry("concurrent.txt", []byte("x"), 5)
		}()
	}
	wg.Wait()

	data, err := u.LoadFile("concurrent.txt")
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if len(data) != 4+n {
		t.Errorf("expected %d bytes, got %d (some appends lost)", 4+n, len(data))
	}
}
