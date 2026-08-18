package client

// CS161 Project 2 - 类型定义
// 业务域：知识管理域（结构定义层）
// 包含所有数据结构：User / FileView / FileMetadata / FileChunk / ShareEntry / Invitation / SignedShareList

import (
	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

// User 用户结构：包含用户身份、密钥（master/file）、PKE/DS 密钥对
type User struct {
	Username   string
	MasterKey  []byte
	FileKey    []byte
	PublicKey  userlib.PKEEncKey
	PrivateKey userlib.PKEDecKey
	SignKey    userlib.DSSignKey
	VerifyKey  userlib.DSVerifyKey
}

// FileView 文件视图：用户视角的文件句柄，指向 FileMetadata
type FileView struct {
	MetadataUUID uuid.UUID
	EncKey       []byte
	HMACKey      []byte
	Status       string               // Own | Shared | Received
	PendingInv   map[string]uuid.UUID // recipientUsername → invitationPtr
}

// FileMetadata 文件元数据：包含 chunk 链表指针、文件密钥、共享列表地址、版本号
type FileMetadata struct {
	Owner         string
	FileName      string
	HeadPtr       uuid.UUID
	TailPtr       uuid.UUID
	NumberChunk   int
	FileEncKey    []byte
	HMACKey       []byte
	ShareListAddr uuid.UUID
	Version       uint64
}

// FileChunk 文件分块：链表节点，Data + 指向下一个 chunk 的 UUID
type FileChunk struct {
	Data []byte    // 加密后的文件内容（或明文，然后用 FileEncKey 加密）
	Next uuid.UUID // 指向下一个 Chunk（或空 UUID 表示终止）
}

// ShareEntry 共享条目：记录谁共享给谁，以及接收方的 FileKey
type ShareEntry struct {
	Sender       string
	Recipient    string
	FileKey      []byte // fileKey of recipient
	MetadataUUID uuid.UUID
	Filename     string // recipient's filename (may be different from sender's filename)
}

// Invitation 文件共享邀请结构
type Invitation struct {
	EncView      []byte // AES 加密的 FileView
	EncryptedKey []byte // 用 RSA 加密的对称密钥
	SenderSig    []byte
}

// SignedShareList 共享列表：map[sender][]ShareEntry，记录所有共享关系
type SignedShareList struct {
	List map[string][]ShareEntry
}

// Directory 目录结构（B05 新增）
// 借鉴学城权限继承模型：子文档默认继承父目录权限
type Directory struct {
	Owner         string
	DirName       string
	ParentDirID   *uuid.UUID // nil = 根目录
	Children      []uuid.UUID // 子目录 + 子文件
	Permissions   []Permission
	InheritParent bool // 默认 true
}

// Permission 权限条目
type Permission struct {
	Subject     string // username / group_id / dept_path
	SubjectType string // "user" / "group" / "dept"
	PermLevel   int    // 1-5
}

// 5 级权限常量（借鉴学城）
const (
	PermBrowse        = 1 // 文档浏览
	PermEdit          = 2 // 文档编辑
	PermEditAdd       = 3 // 编辑 + 添加子文档
	PermEditAddDelete = 4 // 编辑 + 添加 + 删除
	PermManage        = 5 // 管理（设置权限、全部功能）
)

// SubjectIdentity 授权主体身份
type SubjectIdentity struct {
	Type    string // "user" / "group" / "dept"
	Subject string // mis / group_id / dept_path
}

// NotifyHook 通知回调，由接入层（cmd/cs161-server）注入
// nil 时静默跳过（client 包不依赖具体通知实现，避免循环 import）
// ponytail: 函数变量注入，避免引入 interface；升级路径=事件总线/MQ
var NotifyHook func(recipient, event, payload string)

// Notify 触发通知（如果 hook 已注入）
func Notify(recipient, event, payload string) {
	if NotifyHook != nil {
		NotifyHook(recipient, event, payload)
	}
}

// AppendRetryHook 并发 append 观测 hook，由测试/benchmark 注入
// 每次 AppendWithRetry 结束调用，传入本次累计 retry 次数和最终是否冲突耗尽
// ponytail: 函数变量注入，避免暴露内部状态；生产=nil，零开销
var AppendRetryHook func(retryCount int, exhausted bool)
