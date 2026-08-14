package client

// CS161 Project 2 - 加密原语
// 业务域：基础服务域（密码学层）
// 包含密钥派生、对称加密、混合加密、HMAC 验证等基础密码学操作

import (
	"errors"
	"fmt"

	userlib "github.com/cs161-staff/project2-userlib"
)

// DeriveKeys generates encryption and MAC keys from a key.
func DeriveKeys(pdk []byte, encInput []byte, hmacInput []byte) (encKey []byte, macKey []byte, err error) {
	encKey, err = userlib.HashKDF(pdk, encInput)
	if err != nil {
		return nil, nil, err
	}
	encKey = encKey[:16]

	macKey, err = userlib.HashKDF(pdk, hmacInput)
	if err != nil {
		return nil, nil, err
	}
	macKey = macKey[:16]
	return encKey, macKey, nil
}

// AuthEncrypt encrypts and generates HMAC for integrity.
func AuthEncrypt(key []byte, plaintext []byte) (ciphertext []byte, hmacTag []byte, err error) {
	encKey, macKey, err := DeriveKeys(key, []byte("Encryption"), []byte("HMAC"))
	if err != nil {
		return nil, nil, err
	}
	iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	ciphertext = userlib.SymEnc(encKey, iv, plaintext)
	hmacTag, err = userlib.HMACEval(macKey, ciphertext)
	return ciphertext, hmacTag, err
}

// AuthDecrypt validates HMAC and decrypts.
func AuthDecrypt(key []byte, ciphertext []byte, hmacTag []byte) (plaintext []byte, err error) {
	encKey, macKey, err := DeriveKeys(key, []byte("Encryption"), []byte("HMAC"))
	if err != nil {
		return nil, err
	}
	expectedTag, err := userlib.HMACEval(macKey, ciphertext)
	if err != nil || !userlib.HMACEqual(hmacTag, expectedTag) {
		return nil, errors.New("HMAC verification failed")
	}
	plaintext = userlib.SymDec(encKey, ciphertext)
	return plaintext, nil
}

// EasyEncrypt 用显式 encKey + macKey 加密 + HMAC
func EasyEncrypt(encKey []byte, macKey []byte, plaintext []byte) (ciphertext []byte, hmacTag []byte, err error) {
	iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	ciphertext = userlib.SymEnc(encKey, iv, plaintext)
	hmacTag, err = userlib.HMACEval(macKey, ciphertext)
	return ciphertext, hmacTag, err
}

// EasyDecrypt 用显式 encKey + macKey 验证 HMAC + 解密
func EasyDecrypt(encKey []byte, macKey []byte, ciphertext []byte, hmacTag []byte) (plaintext []byte, err error) {
	expectedTag, err := userlib.HMACEval(macKey, ciphertext)
	if err != nil || !userlib.HMACEqual(hmacTag, expectedTag) {
		userlib.DebugMsg("HMAC verification failed")
		return nil, errors.New("HMAC verification failed")
	}
	plaintext = userlib.SymDec(encKey, ciphertext)
	return plaintext, nil
}

// ZeroBytes 用 0 覆盖字节切片，防止敏感数据仍在内存中
func ZeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// HybridEncrypt 使用混合加密方案加密数据，返回加密后的对称密钥和加密数据
// RSA 加密对称密钥，对称密钥加密数据
func HybridEncrypt(publicKey userlib.PKEEncKey, plaintext []byte) (encryptedSymKey []byte, encryptedData []byte, err error) {
	symKey := userlib.RandomBytes(userlib.AESKeySizeBytes)
	iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	encryptedData = userlib.SymEnc(symKey, iv, plaintext)
	encryptedSymKey, err = userlib.PKEEnc(publicKey, symKey)
	if err != nil {
		return nil, nil, fmt.Errorf("公钥加密失败: %v", err)
	}
	return encryptedSymKey, encryptedData, nil
}

// HybridDecrypt 使用混合加密方案解密数据，返回原始明文
func HybridDecrypt(privateKey userlib.PKEDecKey, encryptedSymKey []byte, encryptedData []byte) (symKey []byte, plaintext []byte, err error) {
	symKey, err = userlib.PKEDec(privateKey, encryptedSymKey)
	if err != nil {
		return nil, nil, fmt.Errorf("私钥解密失败: %v", err)
	}
	if len(symKey) != userlib.AESKeySizeBytes {
		return nil, nil, errors.New("解密得到的对称密钥长度不合法")
	}
	if len(encryptedData) < userlib.AESBlockSizeBytes {
		return nil, nil, errors.New("加密数据长度异常")
	}
	plaintext = userlib.SymDec(symKey, encryptedData)
	return symKey, plaintext, nil
}
