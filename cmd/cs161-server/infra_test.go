package main

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
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
