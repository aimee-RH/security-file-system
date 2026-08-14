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
