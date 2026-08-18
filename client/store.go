package client

// CS161 Project 2 - 存储层（Datastore 操作）
// 业务域：知识生产域（文件存储 + 元数据管理）
// 包含 chunk / metadata / file list / share list 的存储与加载

import (
	"encoding/json"
	"errors"
	"sync"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

// metadataMu 保护 SaveFileMetadataWithVersion 的 Load+Check+Store 原子性
// ponytail: per-UUID 锁，避免全局锁瓶颈；升级路径=分片锁或 CAS-based Datastore
var metadataMu sync.Map // uuid.UUID → *sync.Mutex

// datastoreMu 全局 datastore 访问锁
// ponytail: userlib.DatastoreGet/Set/Delete 内部 map 操作非线程安全（见 userlib.go:135）
// 多 goroutine 并发 append 时 LoadUserFileList 触发 fatal "concurrent map read and map write"
// 全局锁是最低成本修复；升级路径=分片锁或换线程安全 datastore
var datastoreMu sync.Mutex

// DSGet 线程安全的 DatastoreGet 封装
func DSGet(id uuid.UUID) ([]byte, bool) {
	datastoreMu.Lock()
	defer datastoreMu.Unlock()
	return userlib.DatastoreGet(id)
}

// DSSet 线程安全的 DatastoreSet 封装
func DSSet(id uuid.UUID, val []byte) {
	datastoreMu.Lock()
	defer datastoreMu.Unlock()
	userlib.DatastoreSet(id, val)
}

// DSDelete 线程安全的 DatastoreDelete 封装
func DSDelete(id uuid.UUID) {
	datastoreMu.Lock()
	defer datastoreMu.Unlock()
	userlib.DatastoreDelete(id)
}

// ErrStepVersionConflict 客户端版本号与服务端不一致（文档被他人同时编辑）
// 借鉴学城 stepVersion 机制
var ErrStepVersionConflict = errors.New("step version conflict: document modified by others")

// File Chunk Helper

// SaveFileChunk 加密并保存文件分块
// ponytail: HMAC 输入包含 chunk UUID，防 chunk swap/mix-up attack
func SaveFileChunk(fileEncKey []byte, fileHMACKey []byte, id uuid.UUID, chunk *FileChunk) error {
	chunkBytes, err := json.Marshal(chunk)
	if err != nil {
		return errors.New("chunk data fail to encode")
	}

	iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	chunkEnc := userlib.SymEnc(fileEncKey, iv, chunkBytes)

	// HMAC时加上当前ID（防 chunk mix-up attack）
	hmacInput := append([]byte{}, chunkEnc...)
	hmacInput = append(hmacInput, id[:]...)
	chunkHMAC, err := userlib.HMACEval(fileHMACKey, hmacInput)

	if err != nil {
		return err
	}
	DSSet(id, append(chunkEnc, chunkHMAC...))
	return nil
}

// LoadFileChunk 验证 HMAC 并解密文件分块
func LoadFileChunk(fileEncKey []byte, fileHMACKey []byte, id uuid.UUID) (*FileChunk, error) {
	raw, ok := DSGet(id)
	if !ok {
		return nil, errors.New("file Chunk not exist")
	}
	hmacSize := userlib.HashSizeBytes
	if len(raw) < 16+hmacSize { // UUID + HMAC
		return nil, errors.New("chunk data corrupted")
	}

	chunkHMAC := raw[len(raw)-hmacSize:]
	chunkEnc := raw[:len(raw)-hmacSize]

	var fileChunk FileChunk
	hmacInput := append([]byte{}, chunkEnc...)
	hmacInput = append(hmacInput, id[:]...)

	expectedTag, err := userlib.HMACEval(fileHMACKey, hmacInput)
	if err != nil || !userlib.HMACEqual(chunkHMAC, expectedTag) {
		userlib.DebugMsg("HMAC verification failed")
		return nil, errors.New("HMAC verification failed")
	}
	fileChunkByte := userlib.SymDec(fileEncKey, chunkEnc)

	err = json.Unmarshal(fileChunkByte, &fileChunk)
	if err != nil {
		return nil, errors.New("chunk data fail to decode")
	}

	return &fileChunk, nil
}

// File Metadata Helper

// SaveFileMetadata 加密并保存文件元数据
func SaveFileMetadata(id uuid.UUID, meta *FileMetadata, encKey, hmacKey []byte) error {
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	cipher, tag, err := EasyEncrypt(encKey, hmacKey, metaBytes)
	if err != nil {
		return err
	}
	DSSet(id, append(cipher, tag...))
	return nil
}

// SaveFileMetadataWithVersion 带乐观锁的保存：加载当前版本，
// 与 expectedVersion 不匹配返回 ErrStepVersionConflict，匹配则保存新版本。
// 借鉴学城 stepVersion 机制，解决多设备并发写入覆盖问题。
//
// 用 per-UUID sync.Mutex 保护 Load+Check+Store 原子性，多 goroutine 真并发安全
func SaveFileMetadataWithVersion(id uuid.UUID, meta *FileMetadata, encKey, hmacKey []byte, expectedVersion uint64) error {
	mu, _ := metadataMu.LoadOrStore(id, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
	defer mu.(*sync.Mutex).Unlock()

	return saveFileMetadataWithVersionLocked(id, meta, encKey, hmacKey, expectedVersion)
}

// saveFileMetadataWithVersionLocked 无锁版本，调用方必须持有 metadataMu[id] 锁
// ponytail: 拆出来给 AppendToFile 用——AppendToFile 把整个 LoadMeta+SaveChunk+SaveMeta 关键段放在同一把锁内，
// 避免多 goroutine 读到相同 TailPtr 后互相覆盖 chunk 链表
func saveFileMetadataWithVersionLocked(id uuid.UUID, meta *FileMetadata, encKey, hmacKey []byte, expectedVersion uint64) error {
	cur, err := LoadFileMetadata(id, encKey, hmacKey)
	if err == nil && cur.Version != expectedVersion {
		return ErrStepVersionConflict
	}
	// err != nil 表示 metadata 不存在（首次创建），允许保存

	return SaveFileMetadata(id, meta, encKey, hmacKey)
}

// lockMetadata 获取 per-metadataUUID 锁（供 AppendToFile 关键段使用）
func lockMetadata(id uuid.UUID) func() {
	mu, _ := metadataMu.LoadOrStore(id, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
	return func() { mu.(*sync.Mutex).Unlock() }
}

// LoadFileMetadata 验证 HMAC 并解密文件元数据
func LoadFileMetadata(id uuid.UUID, encKey []byte, HMACKey []byte) (*FileMetadata, error) {
	raw, ok := DSGet(id)
	if !ok {
		return nil, errors.New("metadata not found")
	}

	hmacSize := userlib.HashSizeBytes
	if len(raw) <= hmacSize {
		return nil, errors.New("invalid metadata length")
	}

	metadataHMAC := raw[len(raw)-hmacSize:]
	metadataEnc := raw[:len(raw)-hmacSize]

	// Verify HMAC
	expectedHMAC, err := userlib.HMACEval(HMACKey, metadataEnc)
	if err != nil {
		return nil, errors.New("failed to compute HMAC")
	}
	if !userlib.HMACEqual(metadataHMAC, expectedHMAC) {
		return nil, errors.New("metadata HMAC mismatch")
	}

	// Decrypt metadata
	var meta FileMetadata
	metadataByte := userlib.SymDec(encKey, metadataEnc)
	err = json.Unmarshal(metadataByte, &meta)

	if err != nil {
		return nil, errors.New("fail to decode")
	}
	return &meta, nil
}

// LoadUserFileList 加载并验证用户文件列表
func LoadUserFileList(id uuid.UUID, fileListEncKey []byte, fileListHMACKey []byte, isFirst bool) (fileList map[string]FileView, err error) {
	userFileListStore, exist := DSGet(id)
	if !exist {
		if !isFirst {
			userlib.DebugMsg("user file list not found")
			return nil, errors.New("user file list not found")
		}
		return make(map[string]FileView), nil
	}

	if len(userFileListStore) < 64 {
		userlib.DebugMsg("stored file list too short to contain HMAC")
		return nil, errors.New("corrupted file list: too short")
	}

	fileListEnc := userFileListStore[:len(userFileListStore)-64]
	fileListHMAC := userFileListStore[len(userFileListStore)-64:]

	userFileListByte, err := EasyDecrypt(fileListEncKey, fileListHMACKey, fileListEnc, fileListHMAC)
	if err != nil {
		userlib.DebugMsg("failed to decrypt user file list")
		return nil, errors.New("failed to decrypt user file list")
	}

	fileList = make(map[string]FileView)
	err = json.Unmarshal(userFileListByte, &fileList)
	if err != nil {
		userlib.DebugMsg("failed to decode user file list JSON")
		return nil, errors.New("failed to decode user file list")
	}

	return fileList, nil
}

// SaveUserFileList 加密并保存用户文件列表
func SaveUserFileList(uuid uuid.UUID, encKey, macKey []byte, list map[string]FileView) error {
	data, err := json.Marshal(list)
	if err != nil {
		return err
	}
	cipher, tag, err := EasyEncrypt(encKey, macKey, data)
	if err != nil {
		return err
	}
	DSSet(uuid, append(cipher, tag...))
	return nil
}

// LoadSignedShareList 加载共享列表
func LoadSignedShareList(shareListAddr uuid.UUID) (*SignedShareList, error) {
	shareListBytes, ok := DSGet(shareListAddr)
	if !ok {
		return nil, errors.New("RevokeAccess: ShareList not found")
	}
	var signedList SignedShareList
	err := json.Unmarshal(shareListBytes, &signedList)
	if err != nil {
		return nil, err
	}
	return &signedList, nil
}

// SaveSignedShareList 保存共享列表
func SaveSignedShareList(shareListAddr uuid.UUID, signedList *SignedShareList) error {
	updatedSignedList, err := json.Marshal(signedList)
	if err != nil {
		return errors.New("error decode ShareList")
	}
	DSSet(shareListAddr, updatedSignedList)
	return nil
}

// VerifyFileIntegrity 遍历 chunk 链表验证完整性
func VerifyFileIntegrity(meta *FileMetadata) error {
	current := meta.HeadPtr
	count := 0
	for count < meta.NumberChunk {
		chunk, err := LoadFileChunk(meta.FileEncKey, meta.HMACKey, current)
		if err != nil {
			return errors.New("Verify: fail to load chunk")
		}
		current = chunk.Next
		count++
	}
	if count != meta.NumberChunk {
		return errors.New("Verify: chunk count mismatch")
	}
	return nil
}
