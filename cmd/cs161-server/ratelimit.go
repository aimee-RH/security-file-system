package main

// CS161 Project 2 - 频次限制
// 业务域：基础服务域（Agent 滥用防护）
// 借鉴学城 Citadel Skill 的"评论类操作每会话每文档 1 次"频次限制
//
// 设计：
//   - 令牌桶简化版：每 N 秒补充 M 个 token，每次请求消耗 1 个
//   - 超限返回 429 Too Many Requests
//   - 按 subject 限流（区分用户/Agent）

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter 令牌桶限流器
// ponytail: 简化实现，in-memory；生产应换 Redis 分布式限流
type RateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*tokenBucket
	maxTokens  int       // 桶容量
	refillRate time.Duration // 补充间隔
	refillAmount int       // 每次补充数量
}

type tokenBucket struct {
	tokens   int
	lastRefill time.Time
}

// NewRateLimiter 构造限流器
// maxTokens=桶容量，refillRate=补充间隔，refillAmount=每次补充数量
func NewRateLimiter(maxTokens int, refillRate time.Duration, refillAmount int) *RateLimiter {
	return &RateLimiter{
		buckets:     make(map[string]*tokenBucket),
		maxTokens:   maxTokens,
		refillRate:  refillRate,
		refillAmount: refillAmount,
	}
}

// Allow 检查是否允许请求
func (r *RateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	bucket, ok := r.buckets[key]
	if !ok {
		bucket = &tokenBucket{
			tokens:     r.maxTokens,
			lastRefill: time.Now(),
		}
		r.buckets[key] = bucket
	}

	// 补充 token
	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill)
	refills := int(elapsed / r.refillRate)
	if refills > 0 {
		bucket.tokens += refills * r.refillAmount
		if bucket.tokens > r.maxTokens {
			bucket.tokens = r.maxTokens
		}
		bucket.lastRefill = now
	}

	// 消耗 token
	if bucket.tokens <= 0 {
		return false
	}
	bucket.tokens--
	return true
}

// DefaultRateLimiter 默认限流器：每用户每秒 10 个请求
var DefaultRateLimiter = NewRateLimiter(10, time.Second, 10)

// RateLimitMiddleware 限流中间件
// 按 identity.Subject 限流
func RateLimitMiddleware(limiter *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := GetIdentity(c)
		if !ok {
			// 无身份（如未认证的请求）按 IP 限流
			id = Identity{Type: "ip", Subject: c.ClientIP()}
		}
		if !limiter.Allow(id.Subject) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded",
				"subject": id.Subject,
			})
			return
		}
		c.Next()
	}
}
