package client

// CS161 Project 2 - 存储层（Datastore 操作）
// 业务域：知识生产域（文件存储 + 元数据管理）
// 包含 chunk / metadata / file list / share list 的存储与加载

import (
	"encoding/json"
	"errors"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

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
	userlib.DatastoreSet(id, append(chunkEnc, chunkHMAC...))
	return nil
}

// LoadFileChunk 验证 HMAC 并解密文件分块
func LoadFileChunk(fileEncKey []byte, fileHMACKey []byte, id uuid.UUID) (*FileChunk, error) {
	raw, ok := userlib.DatastoreGet(id)
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
	userlib.DatastoreSet(id, append(cipher, tag...))
	return nil
}

// SaveFileMetadataWithVersion 带乐观锁的保存：加载当前版本，
// 与 expectedVersion 不匹配返回 ErrStepVersionConflict，匹配则保存新版本。
// 借鉴学城 stepVersion 机制，解决多设备并发写入覆盖问题。
//
// ponytail: CS161 限制不允许 import sync，单线程版本；多设备真并发冲突检测留到 B02 拆分后用 userlib 外层包同步
// 当前实现：单线程下版本检测有效；多线程下 Load+Check+Store 不原子（已知限制）
func SaveFileMetadataWithVersion(id uuid.UUID, meta *FileMetadata, encKey, hmacKey []byte, expectedVersion uint64) error {
	// 加载当前 metadata
	cur, err := LoadFileMetadata(id, encKey, hmacKey)
	if err == nil && cur.Version != expectedVersion {
		return ErrStepVersionConflict
	}
	// err != nil 表示 metadata 不存在（首次创建），允许保存

	return SaveFileMetadata(id, meta, encKey, hmacKey)
}

// LoadFileMetadata 验证 HMAC 并解密文件元数据
func LoadFileMetadata(id uuid.UUID, encKey []byte, HMACKey []byte) (*FileMetadata, error) {
	raw, ok := userlib.DatastoreGet(id)
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
	userFileListStore, exist := userlib.DatastoreGet(id)
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
	userlib.DatastoreSet(uuid, append(cipher, tag...))
	return nil
}

// LoadSignedShareList 加载共享列表
func LoadSignedShareList(shareListAddr uuid.UUID) (*SignedShareList, error) {
	shareListBytes, ok := userlib.DatastoreGet(shareListAddr)
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
	userlib.DatastoreSet(shareListAddr, updatedSignedList)
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
