package client

// CS161 Project 2 - 用户认证
// 业务域：基础服务域（用户身份管理）
// InitUser / GetUser：argon2KDF 派生 masterKey + PKE/DS 密钥对

import (
	"encoding/json"
	"errors"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

// InitUser 创建并初始化新用户
func InitUser(username string, password string) (*User, error) {
	if len(username) == 0 {
		return nil, errors.New("username cannot be empty")
	}

	// 防重复
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte("user_" + username))[:16])
	if err != nil {
		return nil, err
	}
	if _, ok := DSGet(userUUID); ok {
		return nil, errors.New("InitUser: user already exists")
	}

	// 密钥对生成
	publicKey, privateKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	signKey, verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	// 密码派生密钥
	salt := userlib.RandomBytes(16)
	pdk := userlib.Argon2Key([]byte(password), salt, 16)

	// store PKE and DS public keys in keystore
	userlib.KeystoreSet(username+"_PK", publicKey)
	userlib.KeystoreSet(username+"_DS", verifyKey)

	// 构造用户数据
	userdata := User{
		Username:   username,
		MasterKey:  pdk,
		FileKey:    userlib.RandomBytes(16),
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		SignKey:    signKey,
		VerifyKey:  verifyKey,
	}

	// Encrypt user data
	userDataByte, _ := json.Marshal(userdata)
	userByteEnc, userHmacTag, err := AuthEncrypt(pdk, userDataByte)
	if err != nil {
		return nil, errors.New("InitUser: Fail to encrypt user data")
	}

	// Store user data
	finalBytes := append(salt, userByteEnc...)
	finalBytes = append(finalBytes, userHmacTag...)
	DSSet(userUUID, finalBytes)

	return &userdata, nil
}

// GetUser 验证并加载用户
func GetUser(username string, password string) (*User, error) {
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte("user_" + username))[:16])
	if err != nil {
		return nil, err
	}
	stored, ok := DSGet(userUUID)
	if !ok {
		return nil, errors.New("user not found")
	}
	if len(stored) < 16+userlib.HashSizeBytes {
		return nil, errors.New("user corrupted: length too short")
	}

	salt := stored[:16]
	userByteEnc := stored[16 : len(stored)-userlib.HashSizeBytes]
	userHmacTag := stored[len(stored)-userlib.HashSizeBytes:]

	pdk := userlib.Argon2Key([]byte(password), salt, 16)

	// 验证并解密 user data
	userdataBytes, err := AuthDecrypt(pdk, userByteEnc, userHmacTag)
	if err != nil {
		return nil, errors.New("GetUer: Invalid password or tampered data")
	}

	var userdata User
	err = json.Unmarshal(userdataBytes, &userdata)
	if err != nil {
		return nil, err
	}

	return &userdata, nil
}
