package main

// CS161 Project 2 - 鉴权层
// 业务域：基础服务域（用户 + Agent 身份鉴权）
// 借鉴学城 Citadel Skill 的 SSO + Agent 身份鉴权机制
//
// 设计：
//   - IssueToken(identity) 生成随机 token 存入 in-memory TokenStore
//   - AuthMiddleware 检查 Authorization: Bearer <token>，无 token 或无效返回 401
//   - Identity.Type 区分 "user" / "agent"

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Identity 操作者身份
type Identity struct {
	Type      string    // "user" / "agent"
	Subject   string    // 用户名 / Agent ID
	ExpiresAt time.Time // token 过期时间
}

// TokenStore in-memory token 存储（生产应换 Redis 等）
// ponytail: 简化实现，单进程内有效
var TokenStore = struct {
	sync.RWMutex
	m map[string]Identity
}{m: make(map[string]Identity)}

// IssueToken 生成随机 token 并绑定身份
func IssueToken(identity Identity) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)

	TokenStore.Lock()
	TokenStore.m[token] = identity
	TokenStore.Unlock()

	return token, nil
}

// VerifyToken 验证 token 有效性
func VerifyToken(token string) (Identity, bool) {
	TokenStore.RLock()
	defer TokenStore.RUnlock()

	id, ok := TokenStore.m[token]
	if !ok {
		return Identity{}, false
	}
	if !id.ExpiresAt.IsZero() && time.Now().After(id.ExpiresAt) {
		return Identity{}, false // 过期
	}
	return id, true
}

// RevokeToken 撤销 token
func RevokeToken(token string) {
	TokenStore.Lock()
	delete(TokenStore.m, token)
	TokenStore.Unlock()
}

// AuthMiddleware 鉴权中间件
// 检查 Authorization: Bearer <token>
// 无 token / 无效 / 过期 → 401
// 通过 → 把 Identity 写入 gin.Context
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}

		// 期望格式: "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization format"})
			return
		}

		id, ok := VerifyToken(parts[1])
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		c.Set("identity", id)
		c.Next()
	}
}

// GetIdentity 从 gin.Context 取出 identity（供 handler 使用）
func GetIdentity(c *gin.Context) (Identity, bool) {
	v, ok := c.Get("identity")
	if !ok {
		return Identity{}, false
	}
	id, ok := v.(Identity)
	return id, ok
}
