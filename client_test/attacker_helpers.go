package client_test

// import (
// 	// Some imports use an underscore to prevent the compiler from complaining
// 	// about unused imports.

// 	_ "encoding/hex"
// 	"encoding/json"
// 	_ "encoding/json"
// 	_ "errors"
// 	_ "strconv"
// 	_ "strings"

// 	"github.com/google/uuid"
// 	_ "github.com/google/uuid"

// 	userlib "github.com/cs161-staff/project2-userlib"

// 	"github.com/cs161-staff/project2-starter-code/client"
// )

// ///////////////////////////
// // 🧪 模拟结构体（映射你的 UserMetadata）
// ///////////////////////////

// type SimulatedUserMetadata struct {
// 	EncryptedPrivateKey       []byte
// 	PublicKey                 []byte
// 	SignatureKey              []byte
// 	RootFilePointer           []byte
// 	FileMappings              map[string]uuid.UUID
// 	FileMappingsEncryptedKeys map[string][]byte // 仅用于测试攻击者记忆 EncryptedKey
// }

// ///////////////////////////
// // 🧠 从 Datastore 提取用户 Metadata（模拟攻击者记忆的内容）
// ///////////////////////////

// func extractUserMetadata(user *client.User) SimulatedUserMetadata {
// 	metaUUIDBytes := userlib.Hash([]byte(user.Username + "metadata"))[:16]
// 	metaUUID, _ := uuid.FromBytes(metaUUIDBytes)

// 	raw, ok := userlib.DatastoreGet(metaUUID)
// 	if !ok {
// 		panic("UserMetadata not found for user: " + user.Username)
// 	}

// 	var meta SimulatedUserMetadata
// 	err := json.Unmarshal(raw, &meta)
// 	if err != nil {
// 		panic("Failed to parse UserMetadata for user: " + err.Error())
// 	}

// 	return meta
// }

// ///////////////////////////
// // 🔓 攻击者可读取的模拟接口
// ///////////////////////////

// // 获取指定文件的 FileUUID
// func attackerGetFileUUID(user *client.User, filename string) uuid.UUID {
// 	meta := extractUserMetadata(user)
// 	return meta.FileMappings[filename]
// }

// // 获取某文件在接收 invitation 时存储的 EncryptedFileKey（需你在 AcceptInvitation 中记录）
// func attackerRememberEncryptedKey(user *client.User, filename string) []byte {
// 	meta := extractUserMetadata(user)
// 	return meta.FileMappingsEncryptedKeys[filename]
// }

// // 尝试用旧 EncryptedFileKey（模拟 Replay）伪造访问（实际上无法操作底层 key 解密，只能模拟）
// func attackerForgeLoadWithOldEncryptedKey(user *client.User, fileUUID uuid.UUID, encryptedKey []byte) bool {
// 	// 模拟攻击者试图访问旧文件路径
// 	// 实际只能通过 LoadFile 尝试加载旧映射（应该失败）
// 	_, err := user.LoadFile("fromAlice") // 假设 fromAlice 是 revoked 共享路径
// 	return err == nil
// }

// ///////////////////////////
// // 🎯 模拟暴力攻击（猜测 UUID、读取块）
// ///////////////////////////

// // 猜测若干 UUID（例如：用 hash-based UUID 结构）
// func attackerGuessChunkUUIDs() []uuid.UUID {
// 	var guesses []uuid.UUID
// 	base := userlib.Hash([]byte("knownPattern"))

// 	for i := 0; i < 5; i++ {
// 		uuidGuess, _ := uuid.FromBytes(base[i : i+16])
// 		guesses = append(guesses, uuidGuess)
// 	}

// 	return guesses
// }

// // 尝试读取某个 UUID 是否存在（模拟暴力探测 datastore）
// func attackerTryReadChunk(chunkUUID uuid.UUID) []byte {
// 	data, ok := userlib.DatastoreGet(chunkUUID)
// 	if ok {
// 		return data
// 	}
// 	return nil
// }

// // 修改攻击者已知的 UUID 上的数据（模拟篡改 datastore 内容）
// func attackerDirectlyModifyChunk(user *client.User) bool {
// 	meta := extractUserMetadata(user)

// 	for _, fileUUID := range meta.FileMappings {
// 		data, ok := userlib.DatastoreGet(fileUUID)
// 		if ok && len(data) > 0 {
// 			data[0] ^= 0xFF // Bit flip 攻击
// 			userlib.DatastoreSet(fileUUID, data)
// 			return true
// 		}
// 	}

// 	return false
// }
