package main

// CS161 Project 2 - 通知服务
// 业务域：基础服务域（异步通知）
// 借鉴学城 Citadel Skill 的"撤销时通知相关用户"机制
//
// 设计：
//   - Notify(recipient, event, payload) 异步推送到 in-memory channel
//   - GetNotifications(recipient) 拉取通知
//   - 撤销操作触发通知

import (
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Notification 通知
type Notification struct {
	Timestamp time.Time
	Recipient string // 接收者 username
	Event     string // "revoked" / "shared" / "updated"
	Payload   string // JSON 或简单描述
}

// NotifyStore in-memory 通知存储
// ponytail: 简化实现；生产应换 Mafka/MQ
var NotifyStore = struct {
	sync.RWMutex
	queue map[string][]Notification // recipient → notifications
}{queue: make(map[string][]Notification)}

// Notify 异步推送通知（in-memory 同步写入，但语义上是异步事件）
func Notify(recipient, event, payload string) {
	NotifyStore.Lock()
	NotifyStore.queue[recipient] = append(NotifyStore.queue[recipient], Notification{
		Timestamp: time.Now(),
		Recipient: recipient,
		Event:     event,
		Payload:   payload,
	})
	NotifyStore.Unlock()
}

// GetNotifications 拉取指定接收者的所有通知
func GetNotifications(recipient string) []Notification {
	NotifyStore.RLock()
	defer NotifyStore.RUnlock()
	out := make([]Notification, len(NotifyStore.queue[recipient]))
	copy(out, NotifyStore.queue[recipient])
	return out
}

// ClearNotifications 清空通知（测试用）
func ClearNotifications() {
	NotifyStore.Lock()
	NotifyStore.queue = make(map[string][]Notification)
	NotifyStore.Unlock()
}

// NotifyHandler GET /api/notifications?recipient=X
func NotifyHandler(c *gin.Context) {
	recipient := c.Query("recipient")
	if recipient == "" {
		c.JSON(400, gin.H{"error": "recipient required"})
		return
	}
	notifications := GetNotifications(recipient)
	c.JSON(200, gin.H{"notifications": notifications, "count": len(notifications)})
}
