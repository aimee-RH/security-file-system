package main

// CS161 Project 2 - REST API 服务
// 业务域：基础服务域（Agent 接入层 HTTP API）
// 借鉴学城 Citadel Skill 的 REST 设计，通过 gin 包装 client 包核心函数

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/cs161-staff/project2-starter-code/client"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// APIRequest 通用请求体
// 不同 endpoint 用不同字段，未用的字段保持 zero value
type APIRequest struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	Filename     string `json:"filename"`
	Data         string `json:"data"`
	Recipient    string `json:"recipient"`
	Sender       string `json:"sender"`
	InvitationID string `json:"invitation_id"`
}

// newRouter 构造 gin router，挂载所有 API endpoint
// 抽成函数方便测试用 httptest 调用
func newRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	api := r.Group("/api")
	{
		api.POST("/users/init", handleUserInit)
		api.POST("/files/store", handleFileStore)
		api.GET("/files/load", handleFileLoad)
		api.POST("/files/append", handleFileAppend)
		api.POST("/share/invite", handleShareInvite)
		api.POST("/share/accept", handleShareAccept)
		api.POST("/share/revoke", handleShareRevoke)
	}

	return r
}

// handleUserInit POST /api/users/init
func handleUserInit(c *gin.Context) {
	var req APIRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, err := client.InitUser(req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("user init failed: %v", err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "username": req.Username})
}

// handleFileStore POST /api/files/store
func handleFileStore(c *gin.Context) {
	var req APIRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	u, err := client.GetUser(req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("get user failed: %v", err)})
		return
	}
	if err := u.StoreFile(req.Filename, []byte(req.Data)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("store file failed: %v", err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "bytes": len(req.Data)})
}

// handleFileLoad GET /api/files/load?username=X&password=Y&filename=Z
func handleFileLoad(c *gin.Context) {
	username := c.Query("username")
	password := c.Query("password")
	filename := c.Query("filename")
	if username == "" || password == "" || filename == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username, password, filename are required"})
		return
	}
	u, err := client.GetUser(username, password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("get user failed: %v", err)})
		return
	}
	data, err := u.LoadFile(filename)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("load file failed: %v", err)})
		return
	}
	c.Data(http.StatusOK, "application/octet-stream", data)
}

// handleFileAppend POST /api/files/append
func handleFileAppend(c *gin.Context) {
	var req APIRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	u, err := client.GetUser(req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("get user failed: %v", err)})
		return
	}
	// 用 AppendWithRetry 自带 stepVersion 乐观锁 + 重试
	if err := u.AppendWithRetry(req.Filename, []byte(req.Data), 3); err != nil {
		// 区分 stepVersion 冲突和其他错误
		if strings.Contains(err.Error(), "max retry exceeded") {
			c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("conflict: %v", err)})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("append file failed: %v", err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "appended": len(req.Data)})
}

// handleShareInvite POST /api/share/invite
func handleShareInvite(c *gin.Context) {
	var req APIRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	u, err := client.GetUser(req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("get user failed: %v", err)})
		return
	}
	invID, err := u.CreateInvitation(req.Filename, req.Recipient)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("create invitation failed: %v", err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"invitation_id": invID.String()})
}

// handleShareAccept POST /api/share/accept
func handleShareAccept(c *gin.Context) {
	var req APIRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	u, err := client.GetUser(req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("get user failed: %v", err)})
		return
	}
	invUUID, err := uuid.Parse(req.InvitationID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid invitation id: %v", err)})
		return
	}
	if err := u.AcceptInvitation(req.Sender, invUUID, req.Filename); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("accept invitation failed: %v", err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "filename": req.Filename})
}

// handleShareRevoke POST /api/share/revoke
func handleShareRevoke(c *gin.Context) {
	var req APIRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	u, err := client.GetUser(req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("get user failed: %v", err)})
		return
	}
	if err := u.RevokeAccess(req.Filename, req.Recipient); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("revoke access failed: %v", err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "revoked": req.Recipient})
}

func main() {
	r := newRouter()
	fmt.Println("CS161 server listening on :8080")
	if err := r.Run(":8080"); err != nil {
		panic(err)
	}
}
