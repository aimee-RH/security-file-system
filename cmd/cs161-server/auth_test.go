package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// 接缝 1：IssueToken + VerifyToken
func TestIssueAndVerifyToken(t *testing.T) {
	// 清空 TokenStore
	TokenStore.Lock()
	TokenStore.m = make(map[string]Identity)
	TokenStore.Unlock()

	token, err := IssueToken(Identity{
		Type:      "user",
		Subject:   "alice",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("issue token failed: %v", err)
	}

	id, ok := VerifyToken(token)
	if !ok {
		t.Fatalf("expected token valid, but not")
	}
	if id.Subject != "alice" {
		t.Errorf("expected subject 'alice', got %s", id.Subject)
	}
	if id.Type != "user" {
		t.Errorf("expected type 'user', got %s", id.Type)
	}
}

// 接缝 1：过期 token 验证失败
func TestExpiredToken(t *testing.T) {
	TokenStore.Lock()
	TokenStore.m = make(map[string]Identity)
	TokenStore.Unlock()

	token, _ := IssueToken(Identity{
		Type:      "agent",
		Subject:   "agent-001",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // 已过期
	})

	_, ok := VerifyToken(token)
	if ok {
		t.Errorf("expected expired token to be invalid")
	}
}

// 接缝 2：AuthMiddleware 无 header 返回 401
func TestAuthMiddlewareNoHeader(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(AuthMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// 接缝 2：AuthMiddleware 有效 token 通过
func TestAuthMiddlewareValidToken(t *testing.T) {
	TokenStore.Lock()
	TokenStore.m = make(map[string]Identity)
	TokenStore.Unlock()

	token, _ := IssueToken(Identity{
		Type:    "user",
		Subject: "alice",
	})

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(AuthMiddleware())
	r.GET("/test", func(c *gin.Context) {
		id, ok := GetIdentity(c)
		if !ok {
			c.JSON(500, gin.H{"error": "no identity"})
			return
		}
		c.JSON(200, gin.H{"subject": id.Subject, "type": id.Type})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d; body=%s", w.Code, w.Body.String())
	}
}

// 接缝 3：AuthMiddleware 无效 token 格式返回 401
func TestAuthMiddlewareInvalidFormat(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(AuthMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Basic abc")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// 接缝 3：AuthMiddleware 无效 token 返回 401
func TestAuthMiddlewareInvalidToken(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(AuthMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer nonexistent-token")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// 接缝 3：Agent 身份也能通过鉴权
func TestAuthMiddlewareAgentIdentity(t *testing.T) {
	TokenStore.Lock()
	TokenStore.m = make(map[string]Identity)
	TokenStore.Unlock()

	token, _ := IssueToken(Identity{
		Type:    "agent",
		Subject: "agent-007",
	})

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(AuthMiddleware())
	r.GET("/test", func(c *gin.Context) {
		id, _ := GetIdentity(c)
		c.JSON(200, gin.H{"type": id.Type})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}
