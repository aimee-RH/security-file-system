package main

// CS161 Project 2 - 审计日志
// 业务域：基础服务域（操作审计追溯）
// 借鉴学城 Citadel Skill 的"所有操作携带使用者身份可追溯"机制
//
// 设计：
//   - LogAudit(identity, action, target, result) 记录操作
//   - AuditMiddleware 包裹所有请求，自动记录
//   - in-memory store（生产应换持久化存储）

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// AuditEntry 审计日志条目
type AuditEntry struct {
	Timestamp time.Time
	Type      string // "user" / "agent"
	Subject   string // mis / agent_id
	Action    string // "store" / "load" / "append" / "invite" / "accept" / "revoke"
	Target    string // filename / uuid
	Method    string // HTTP method
	Path      string // request path
	Result    string // "success" / "fail"
	StatusCode int
}

// AuditLogStore in-memory 审计日志存储
// ponytail: 简化实现，单进程内有效；生产应换持久化存储（DB/文件）
var AuditLogStore = struct {
	sync.RWMutex
	entries []AuditEntry
}{entries: []AuditEntry{}}

// LogAudit 记录审计日志
func LogAudit(identity Identity, action, target, result string, statusCode int, method, path string) {
	entry := AuditEntry{
		Timestamp:  time.Now(),
		Type:       identity.Type,
		Subject:    identity.Subject,
		Action:     action,
		Target:     target,
		Method:     method,
		Path:       path,
		Result:     result,
		StatusCode: statusCode,
	}
	AuditLogStore.Lock()
	AuditLogStore.entries = append(AuditLogStore.entries, entry)
	AuditLogStore.Unlock()
}

// GetAuditLog 查询审计日志（按 subject 过滤，空字符串返回全部）
func GetAuditLog(subject string) []AuditEntry {
	AuditLogStore.RLock()
	defer AuditLogStore.RUnlock()

	if subject == "" {
		// 返回全部的副本
		out := make([]AuditEntry, len(AuditLogStore.entries))
		copy(out, AuditLogStore.entries)
		return out
	}

	var out []AuditEntry
	for _, e := range AuditLogStore.entries {
		if e.Subject == subject {
			out = append(out, e)
		}
	}
	return out
}

// ClearAuditLog 清空审计日志（测试用）
func ClearAuditLog() {
	AuditLogStore.Lock()
	AuditLogStore.entries = []AuditEntry{}
	AuditLogStore.Unlock()
}

// AuditMiddleware 审计中间件
// 记录所有请求：身份（从 gin.Context 取）、HTTP 方法、路径、状态码、结果
func AuditMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// 后置记录（拿到 status code 和 result）
		id, _ := GetIdentity(c)
		result := "success"
		if c.Writer.Status() >= 400 {
			result = "fail"
		}
		LogAudit(id, c.Request.Method, "", result, c.Writer.Status(), c.Request.Method, c.Request.URL.Path)
	}
}

// AuditQueryHandler GET /api/audit?subject=X
// 返回指定 subject 的审计日志
func AuditQueryHandler(c *gin.Context) {
	subject := c.Query("subject")
	entries := GetAuditLog(subject)
	c.JSON(http.StatusOK, gin.H{"entries": entries, "count": len(entries)})
}
