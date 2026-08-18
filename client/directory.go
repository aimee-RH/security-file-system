package client

// CS161 Project 2 - 目录与权限继承
// 业务域：知识治理域（权限管理 + 目录树）
// 借鉴学城权限继承模型：子文档默认继承父目录权限，支持移除/恢复继承
//
// 把 CS161 原本"每文件单独 invitation"（O(N) 共享成本）升级为
// "目录级权限继承"（O(1) 共享成本），更适合团队级知识库场景

import (
	"encoding/json"
	"errors"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

// SaveDirectory 加密并保存目录到 Datastore
func SaveDirectory(id uuid.UUID, dir *Directory, encKey, hmacKey []byte) error {
	dirBytes, err := json.Marshal(dir)
	if err != nil {
		return err
	}
	cipher, tag, err := EasyEncrypt(encKey, hmacKey, dirBytes)
	if err != nil {
		return err
	}
	DSSet(id, append(cipher, tag...))
	return nil
}

// LoadDirectory 加载并解密目录
func LoadDirectory(id uuid.UUID, encKey, hmacKey []byte) (*Directory, error) {
	raw, ok := DSGet(id)
	if !ok {
		return nil, errors.New("directory not found")
	}
	hmacSize := userlib.HashSizeBytes
	if len(raw) <= hmacSize {
		return nil, errors.New("invalid directory length")
	}
	dirHMAC := raw[len(raw)-hmacSize:]
	dirEnc := raw[:len(raw)-hmacSize]

	expectedHMAC, err := userlib.HMACEval(hmacKey, dirEnc)
	if err != nil {
		return nil, errors.New("failed to compute HMAC")
	}
	if !userlib.HMACEqual(dirHMAC, expectedHMAC) {
		return nil, errors.New("directory HMAC mismatch")
	}

	dirBytes := userlib.SymDec(encKey, dirEnc)
	var dir Directory
	if err := json.Unmarshal(dirBytes, &dir); err != nil {
		return nil, errors.New("failed to decode directory")
	}
	return &dir, nil
}

// MatchSubject 检查权限条目是否匹配身份
func MatchSubject(p Permission, identity SubjectIdentity) bool {
	if p.SubjectType != identity.Type {
		return false
	}
	return p.Subject == identity.Subject
}

// ResolvePermission 递归解析权限：先查目录自身显式权限，再向上查父目录（如继承）
// 返回 PermLevel（1-5），0 表示无权限
//
// 借鉴学城继承模型：
//   - 子文档默认继承父目录权限
//   - 显式权限优先于继承
//   - InheritParent=false 时切断继承
func ResolvePermission(dirID uuid.UUID, encKey, hmacKey []byte, identity SubjectIdentity) (int, error) {
	dir, err := LoadDirectory(dirID, encKey, hmacKey)
	if err != nil {
		return 0, err
	}

	// 1. 先查目录自身的显式权限
	for _, p := range dir.Permissions {
		if MatchSubject(p, identity) {
			return p.PermLevel, nil
		}
	}

	// 2. 如果继承父目录，递归向上查
	if dir.InheritParent && dir.ParentDirID != nil {
		return ResolvePermission(*dir.ParentDirID, encKey, hmacKey, identity)
	}

	return 0, nil
}

// GrantPermission 给目录添加权限条目
func GrantPermission(dir *Directory, identity SubjectIdentity, level int) {
	// 先检查是否已有同主体的权限，有则更新
	for i, p := range dir.Permissions {
		if MatchSubject(p, identity) {
			dir.Permissions[i].PermLevel = level
			return
		}
	}
	// 没有则新增
	dir.Permissions = append(dir.Permissions, Permission{
		Subject:     identity.Subject,
		SubjectType: identity.Type,
		PermLevel:   level,
	})
}

// RemoveInheritance 切断继承（InheritParent=false）
// 借鉴学城 inherit --action remove
func RemoveInheritance(dir *Directory) {
	dir.InheritParent = false
}

// RestoreInheritance 恢复继承
// 借鉴学城 inherit --action restore，可选保留已有显式权限
func RestoreInheritance(dir *Directory, keepExisting bool) {
	dir.InheritParent = true
	if !keepExisting {
		dir.Permissions = nil
	}
}
