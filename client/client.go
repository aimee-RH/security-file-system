package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"
	// "bytes"
	// "crypto/rsa"
	// "crypto/x509"
	// "encoding/json"
	// "encoding/pem"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
// type User struct {
// 	Username string

// 	// You can add other attributes here if you want! But note that in order for attributes to
// 	// be included when this struct is serialized to/from JSON, they must be capitalized.
// 	// On the flipside, if you have an attribute that you want to be able to access from
// 	// this struct's methods, but you DON'T want that value to be included in the serialized value
// 	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
// 	// begins with a lowercase letter).
// }

type User struct {
	Username   string
	MasterKey  []byte
	FileKey    []byte
	PublicKey  userlib.PKEEncKey
	PrivateKey userlib.PKEDecKey
	SignKey    userlib.DSSignKey
	VerifyKey  userlib.DSVerifyKey
}

type FileView struct {
	MetadataUUID uuid.UUID
	EncKey       []byte
	HMACKey      []byte
	Status       string               // Own | Shared | Received
	PendingInv   map[string]uuid.UUID // recipientUsername → invitationPtr
}

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

type FileChunk struct {
	Data []byte    // 加密后的文件内容（或明文，然后用 FileEncKey 加密）
	Next uuid.UUID // 指向下一个 Chunk（或空 UUID 表示终止）
}

type ShareEntry struct {
	Sender       string
	Recipient    string
	FileKey    []byte // fileKey of recipient
	MetadataUUID uuid.UUID
	Filename     string // recipient's filename (may be different from sender's filename)
}

// 文件共享邀请结构
type Invitation struct {
	EncView      []byte // AES 加密的 FileView
	EncryptedKey []byte // 用 RSA 加密的对称密钥
	SenderSig    []byte
}

type SignedShareList struct {
	List map[string][]ShareEntry
}

// helper function

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

func EasyEncrypt(encKey []byte, macKey []byte, plaintext []byte) (ciphertext []byte, hmacTag []byte, err error) {
	iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	ciphertext = userlib.SymEnc(encKey, iv, plaintext)
	hmacTag, err = userlib.HMACEval(macKey, ciphertext)
	return ciphertext, hmacTag, err
}

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
func HybridEncrypt(publicKey userlib.PKEEncKey, plaintext []byte) (encryptedSymKey []byte, encryptedData []byte, err error) {
	// 生成随机的对称密钥（AES-128）
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

// File Chunk Helper
func SaveFileChunk(fileEncKey []byte, fileHMACKey []byte, id uuid.UUID, chunk *FileChunk) error {
	chunkBytes, err := json.Marshal(chunk)
	if err != nil {
		return errors.New("chunk data fail to encode")
	}

	iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	chunkEnc := userlib.SymEnc(fileEncKey, iv, chunkBytes)

	// HMAC时加上当前ID
	hmacInput := append([]byte{}, chunkEnc...)
	hmacInput = append(hmacInput, id[:]...)
	chunkHMAC, err := userlib.HMACEval(fileHMACKey, hmacInput)

	if err != nil {
		return err
	}
	userlib.DatastoreSet(id, append(chunkEnc, chunkHMAC...))
	return nil
}

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

func LoadUserFileList(id uuid.UUID, fileListEncKey []byte, fileListHMACKey []byte, isFirst bool) (fileList map[string]FileView, err error) {
	userFileListStore, exist := userlib.DatastoreGet(id)
	if !exist {
		if !isFirst {
			userlib.DebugMsg("user file list not found")
			return nil, errors.New("user file list not found")
		}
		return make(map[string]FileView), nil
	}

	// Check that the stored data is at least long enough to contain HMAC (64 bytes)
	if len(userFileListStore) < 64 {
		userlib.DebugMsg("stored file list too short to contain HMAC")
		return nil, errors.New("corrupted file list: too short")
	}

	// Separate encrypted data and HMAC
	fileListEnc := userFileListStore[:len(userFileListStore)-64]
	fileListHMAC := userFileListStore[len(userFileListStore)-64:]

	// Attempt to decrypt and verify
	userFileListByte, err := EasyDecrypt(fileListEncKey, fileListHMACKey, fileListEnc, fileListHMAC)
	if err != nil {
		userlib.DebugMsg("failed to decrypt user file list")
		return nil, errors.New("failed to decrypt user file list")
	}

	// Attempt to decode JSON
	fileList = make(map[string]FileView)
	err = json.Unmarshal(userFileListByte, &fileList)
	if err != nil {
		userlib.DebugMsg("failed to decode user file list JSON")
		return nil, errors.New("failed to decode user file list")
	}

	return fileList, nil
}

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

func SaveSignedShareList(shareListAddr uuid.UUID, signedList *SignedShareList) error {
	updatedSignedList, err := json.Marshal(signedList)
	if err != nil {
		return errors.New("error decode ShareList")
	}
	userlib.DatastoreSet(shareListAddr, updatedSignedList)
	return nil
}

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

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (*User, error) {
	// 用户名非空
	if len(username) == 0 {
		return nil, errors.New("username cannot be empty")
	}

	// 防重复
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte("user_" + username))[:16])
	// userlib.DebugMsg("InitUser: userUUID: %v\n", userUUID)
	if err != nil {
		return nil, err
	}
	if _, ok := userlib.DatastoreGet(userUUID); ok {
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

	//store PKE and DS public keys in keystore
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

	//Encrypt user data
	userDataByte, _ := json.Marshal(userdata)
	userByteEnc, userHmacTag, err := AuthEncrypt(pdk, userDataByte)
	if err != nil {
		return nil, errors.New("InitUser: Fail to encrypt user data")
	}

	//Store user data
	finalBytes := append(salt, userByteEnc...)
	finalBytes = append(finalBytes, userHmacTag...)
	userlib.DatastoreSet(userUUID, finalBytes)

	// 返回 User
	return &userdata, nil
}

func GetUser(username string, password string) (*User, error) {
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte("user_" + username))[:16])
	if err != nil {
		return nil, err
	}
	stored, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return nil, errors.New("user not found")
	}
	if len(stored) < 16+userlib.HashSizeBytes {
		return nil, errors.New("user corrupted: length too short")
	}

	// Split salt, userByteEnc, userHmacTag
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

func (userdata *User) StoreFile(filename string, data []byte) (err error) {
	// 生成 FileKey和首个 ChunkKey
	userFileListID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "fileList"))[:16])
	if err != nil {
		return err
	}
	// userlib.DebugMsg("StoreFile: userFileListID: %v\n", userFileListID)
	fileListEncKey, fileListHMACKey, err := DeriveKeys(userdata.FileKey, []byte("fileListEncKey"), []byte("fileListHMACKey"))
	if err != nil {
		return err
	}

	fileList, err := LoadUserFileList(userFileListID, fileListEncKey, fileListHMACKey, true)
	if err != nil {
		return err
	}
	// userlib.DebugMsg("AFTER STORE Alice fileList: %+v", fileList)
	fileView, exist := fileList[filename]
	chunkCount := 1

	// 当前用户的fileList里没有filename, 创建新fileChunk, fileMetadata, fileView
	if !exist {
		// 生成 ChunkUUIDs 和 fileMetadataUUID
		chunkUUID := uuid.New()
		fileMetadataUUID := uuid.New()
		nextchunkUUID := uuid.New()
		ShareListAddr := uuid.New()
		userlib.DebugMsg("StoreFile: chunkUUID: %v\n", chunkUUID)

		// Chunk层
		// 生成filekeys
		fileEncKey, fileHMACKey, err := DeriveKeys(userlib.RandomBytes(16), []byte("fileEncKey"), []byte("fileHMACKey"))
		if err != nil {
			return err
		}

		fileChunk := FileChunk{
			Data: data,
			Next: nextchunkUUID,
		}

		// 存储 fileChunk
		err = SaveFileChunk(fileEncKey, fileHMACKey, chunkUUID, &fileChunk)
		if err != nil {
			return err
		}

		// metadata层
		fileMetadata := FileMetadata{
			Owner:         userdata.Username,
			FileName:      filename,
			HeadPtr:       chunkUUID,
			TailPtr:       fileChunk.Next,
			NumberChunk:   chunkCount,
			FileEncKey:    fileEncKey,
			HMACKey:       fileHMACKey,
			ShareListAddr: ShareListAddr,
			Version:       1,
		}
		emptyShareList := SignedShareList{
			List: make(map[string][]ShareEntry),
		}

		err = SaveSignedShareList(ShareListAddr, &emptyShareList)
		if err != nil {
			return err
		}

		metadataEncKey, metadataHMACKey, err := DeriveKeys(userlib.RandomBytes(16), []byte("filemetadataEncKey"), []byte("filemetadataHMACKey"))
		if err != nil {
			return err
		}
		err = SaveFileMetadata(fileMetadataUUID, &fileMetadata, metadataEncKey, metadataHMACKey)
		if err != nil {
			return err
		}

		//fileView层
		fileView = FileView{
			EncKey:       metadataEncKey,
			HMACKey:      metadataHMACKey,
			MetadataUUID: fileMetadataUUID,
			Status:       "Own",
		}

		defer ZeroBytes(metadataEncKey)
		defer ZeroBytes(metadataHMACKey)

		fileList[filename] = fileView

	} else {
		// 当前用户的fileList里有filename, 直接更新fileChunk和fileMetadata, filekeys和filemetadatakeys不变
		// 获得当前文件的metadata
		fileMetadataUUID := fileView.MetadataUUID
		metadataEncKey := fileView.EncKey
		metadataHMACKey := fileView.HMACKey
		fileMetadata, err := LoadFileMetadata(fileMetadataUUID, metadataEncKey, metadataHMACKey)
		if err != nil {
			return err
		}

		fileEncKey := fileMetadata.FileEncKey
		fileHMACKey := fileMetadata.HMACKey

		//删除旧文件
		curChunkUUID := fileMetadata.HeadPtr
		for {
			// Load current fileChunk
			fileChunk, err := LoadFileChunk(fileEncKey, fileHMACKey, curChunkUUID)
			if err != nil {
				return errors.New("StoreFile: fail to load old file chunk")
			}

			// delete current fileChunk
			userlib.DatastoreDelete(curChunkUUID)

			if fileChunk.Next == fileMetadata.TailPtr {
				break
			}
			curChunkUUID = fileChunk.Next
		}

		//Create new file and store
		// Chunk层
		// 生成 ChunkUUID
		newChunkUUID := uuid.New()
		nextchunkUUID := uuid.New()
		newFileChunk := FileChunk{
			Data: data,
			Next: nextchunkUUID,
		}
		userlib.DebugMsg("StoreFile: newChunkUUID: %v\n", newChunkUUID)

		// 存储 fileChunk
		err = SaveFileChunk(fileEncKey, fileHMACKey, newChunkUUID, &newFileChunk)
		if err != nil {
			return err
		}

		//metadata层
		fileMetadata.HeadPtr = newChunkUUID
		fileMetadata.TailPtr = newFileChunk.Next
		fileMetadata.NumberChunk = chunkCount
		fileMetadata.Version++
		err = SaveFileMetadata(fileMetadataUUID, fileMetadata, metadataEncKey, metadataHMACKey)
		if err != nil {
			return err
		}

		defer ZeroBytes(metadataEncKey)
		defer ZeroBytes(metadataHMACKey)
	}

	// 更新Datastore中用户的fileList
	err = SaveUserFileList(userFileListID, fileListEncKey, fileListHMACKey, fileList)
	if err != nil {
		return err
	}
	defer ZeroBytes(fileListEncKey)
	defer ZeroBytes(fileListHMACKey)

	return nil
}

func (userdata *User) AppendToFile(filename string, data []byte) error {
	fileListEncKey, fileListHMACKey, err := DeriveKeys(userdata.FileKey, []byte("fileListEncKey"), []byte("fileListHMACKey"))
	if err != nil {
		return err
	}
	userFileListID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "fileList"))[:16])
	if err != nil {
		return err
	}

	fileList, err := LoadUserFileList(userFileListID, fileListEncKey, fileListHMACKey, false)
	if err != nil {
		return err
	}

	fileView, exist := fileList[filename]
	if !exist {
		return errors.New("file view not exist")
	}

	// 获得当前文件的FileMetadata
	fileMetadataUUID := fileView.MetadataUUID
	metadataEncKey := fileView.EncKey
	metadataHMACKey := fileView.HMACKey

	fileMetadata, err := LoadFileMetadata(fileMetadataUUID, metadataEncKey, metadataHMACKey)
	if err != nil || fileMetadata == nil {
		return errors.New("AppendToFile: Failed to load file metadata")
	}
	fileEncKey := fileMetadata.FileEncKey
	fileHMACKey := fileMetadata.HMACKey

	// chunk层
	// 生成新的 Chunk
	newChunkUUID := fileMetadata.TailPtr

	// 生成新的预留位置用于下一次 Append
	newNextChunkUUID := uuid.New()

	// 创建新 Chunk，指向新的预留位置
	fileChunk := FileChunk{
		Data: data,
		Next: newNextChunkUUID, // 更新为新的预留 UUID
	}

	// 存储 fileChunk
	err = SaveFileChunk(fileEncKey, fileHMACKey, newChunkUUID, &fileChunk)
	if err != nil {
		return err
	}

	// metadata层
	fileMetadata.TailPtr = newNextChunkUUID
	fileMetadata.NumberChunk++
	fileMetadata.Version++

	// 存储 fileMetadata
	err = SaveFileMetadata(fileMetadataUUID, fileMetadata, metadataEncKey, metadataHMACKey)
	if err != nil {
		return err
	}

	defer ZeroBytes(metadataEncKey)
	defer ZeroBytes(metadataHMACKey)
	defer ZeroBytes(fileListEncKey)
	defer ZeroBytes(fileListHMACKey)

	return nil
}

func (userdata *User) LoadFile(filename string) ([]byte, error) {
	fileListEncKey, fileListHMACKey, err := DeriveKeys(userdata.FileKey, []byte("fileListEncKey"), []byte("fileListHMACKey"))
	if err != nil {
		return nil, err
	}
	userFileListID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "fileList"))[:16])
	if err != nil {
		return nil, err
	}

	fileList, err := LoadUserFileList(userFileListID, fileListEncKey, fileListHMACKey, false)
	if err != nil {
		return nil, err
	}

	fileView, exist := fileList[filename]
	if !exist {
		return nil, errors.New("file view not exist")
	}

	// 获得当前文件的FileMetadata
	fileMetadataUUID := fileView.MetadataUUID
	metadataEncKey := fileView.EncKey
	metadataHMACKey := fileView.HMACKey
	fileMetadata, err := LoadFileMetadata(fileMetadataUUID, metadataEncKey, metadataHMACKey)
	if err != nil || fileMetadata == nil {
		return nil, errors.New("LoadFile: Failed to load file metadata:File may have been revoked (metadata missing")
	}

	fileEncKey := fileMetadata.FileEncKey
	fileHMACKey := fileMetadata.HMACKey

	var fileData []byte

	// Load File Content
	curChunkUUID := fileMetadata.HeadPtr
	for {
		// Load current fileChunk
		fileChunk, err := LoadFileChunk(fileEncKey, fileHMACKey, curChunkUUID)
		if err != nil {
			return nil, errors.New("LoadFile: chunk data fail to load")
		}

		fileData = append(fileData, fileChunk.Data...)

		if fileChunk.Next == fileMetadata.TailPtr {
			break
		}
		curChunkUUID = fileChunk.Next
	}
	defer ZeroBytes(metadataEncKey)
	defer ZeroBytes(metadataHMACKey)
	defer ZeroBytes(fileListEncKey)
	defer ZeroBytes(fileListHMACKey)
	return fileData, nil
}

// CreateInvitation securely creates an invitation to share a file
func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	// 1: Verify recipient's public key
	recipientPK, ok := userlib.KeystoreGet(recipientUsername + "_PK")
	if !ok {
		return uuid.Nil, errors.New("CreateInvitation: recipient public key not found")
	}

	// 2: Get FileList

	// Step 1: Derive keys for user’s file list
	fileListEncKey, fileListHMACKey, err := DeriveKeys(userdata.FileKey, []byte("fileListEncKey"), []byte("fileListHMACKey"))
	if err != nil {
		return uuid.Nil, err
	}
	userFileListID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "fileList"))[:16])
	if err != nil {
		return uuid.Nil, err
	}

	// Step 2: Load the user's file list
	curFileList, err := LoadUserFileList(userFileListID, fileListEncKey, fileListHMACKey, false)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: Failed to load user file list")
	}

	// Step 3: Check if the fileView exists in the user's list
	curFv, exist := curFileList[filename]
	if !exist {
		return uuid.Nil, errors.New("CreateInvitation: FileView not exist")
	}

	//3. Check metadata and filenode integrity
	curFileMetadataUUID := curFv.MetadataUUID
	curFmEncKey := curFv.EncKey
	curFmHMAC := curFv.HMACKey

	// Step 4: Load and verify FileMetadata
	var metadata *FileMetadata
	metadata, err = LoadFileMetadata(curFileMetadataUUID, curFmEncKey, curFmHMAC)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: Failed to load file metadata: " + err.Error())
	}

	if err := VerifyFileIntegrity(metadata); err != nil {
		return uuid.Nil, err
	}

	//4. Generate FileView copy for invitation
	fvcopy := FileView{
		MetadataUUID: curFileMetadataUUID,
		Status:       "Share",
		HMACKey:      curFmHMAC,
		EncKey:       curFmEncKey,
	}

	// Store viewCopy
	ShareSymKey := userlib.RandomBytes(16)
	ShareHMACKey := userlib.RandomBytes(16)

	viewCopyData, err := json.Marshal(fvcopy)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: Error marshaling viewCopy")
	}
	viewCopyEnc := userlib.SymEnc(ShareSymKey, userlib.RandomBytes(16), viewCopyData)
	viewCopyHMAC, err := userlib.HMACEval(ShareHMACKey, viewCopyEnc)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: Error generating HMAC for viewCopy")
	}
	viewCopyEnc = append(viewCopyEnc, viewCopyHMAC...)
	viewCopyAddr := uuid.New()
	userlib.DatastoreSet(viewCopyAddr, viewCopyEnc)

	// Step 5: Construct and sign invitation with hybrid encryption
	viewBytes, err := json.Marshal(fvcopy)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: Error marshaling FileView")
	}

	encryptedKey, encryptedView, err := HybridEncrypt(recipientPK, viewBytes)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: Error encrypting FileView: " + err.Error())
	}

	sig, err := userlib.DSSign(userdata.SignKey, encryptedView)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: Error signing invitation")
	}

	inv := Invitation{
		EncView:      encryptedView,
		EncryptedKey: encryptedKey,
		SenderSig:    sig,
	}

	// 6. Store invitation and return UUID

	invID := uuid.New()
	// 加上记录
	if curFv.PendingInv == nil {
		curFv.PendingInv = make(map[string]uuid.UUID)
	}
	curFv.PendingInv[recipientUsername] = invID
	curFileList[filename] = curFv

	// 更新用户 fileList
	err = SaveUserFileList(userFileListID, fileListEncKey, fileListHMACKey, curFileList)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: failed to save updated file list")
	}

	invBytes, err := json.Marshal(inv)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: Error marshaling invitation")
	}
	userlib.DatastoreSet(invID, invBytes)

	defer ZeroBytes(fileListEncKey)
	defer ZeroBytes(fileListHMACKey)
	defer ZeroBytes(ShareSymKey)
	defer ZeroBytes(ShareHMACKey)
	defer ZeroBytes(curFmEncKey)
	defer ZeroBytes(curFmHMAC)
	return invID, nil
}

// AcceptInvitation allows a recipient to accept a shared file securely
func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) (err error) {
	// Step 1: Verify sender's signature key
	senderVerifyKey, ok := userlib.KeystoreGet(senderUsername + "_DS")
	if !ok {
		return errors.New("AcceptInvitation: sender's signature key not found")
	}

	// Step 2: Get and parse invitation
	invByte, exist := userlib.DatastoreGet(invitationPtr)

	if !exist || len(invByte) == 0 {
		err := errors.New("AcceptInvitation: invitation missing or revoked")
		fmt.Println("Created error:", err)
		return err
	}

	var curInv Invitation
	err = json.Unmarshal(invByte, &curInv)
	if err != nil {
		return errors.New("AcceptInvitation: Error unmarshaling invitation")
	}
	// fmt.Println("AcceptInvitation get curInv", curInv)

	if len(curInv.EncView) == 0 || len(curInv.EncryptedKey) == 0 || len(curInv.SenderSig) == 0 {
		return errors.New("AcceptInvitation: invitation revoked or malformed")
	}

	// Step 3: Verify EncView signature
	if err := userlib.DSVerify(senderVerifyKey, curInv.EncView, curInv.SenderSig); err != nil {
		return errors.New("AcceptInvitation: invalid invitation signature")
	}

	if curInv.EncryptedKey == nil || curInv.EncView == nil || curInv.SenderSig == nil {
		return errors.New("AcceptInvitation: invalid or revoked invitation data")
	}

	// Step 4: Decrypt EncView → FileView
	_, viewBytes, err := HybridDecrypt(userdata.PrivateKey, curInv.EncryptedKey, curInv.EncView)
	if err != nil {
		return errors.New("AcceptInvitation: cannot decrypt FileView: " + err.Error())
	}

	var view FileView
	err = json.Unmarshal(viewBytes, &view)
	if err != nil {
		return errors.New("AcceptInvitation: cannot unmarshal FileView")
	}

	// Step 5: Verify FileView status
	if view.Status != "Share" {
		return errors.New("AcceptInvitation: invalid FileView status")
	}

	//5. Get file list

	// 1. Derive keys using helper
	fileListEncKey, fileListHMACKey, err := DeriveKeys(userdata.FileKey, []byte("fileListEncKey"), []byte("fileListHMACKey"))
	if err != nil {
		return errors.New("AcceptInvitation: failed to derive file list keys")
	}

	// 2. Compute UUID of user's file list
	UserFileListAddr, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "fileList"))[:16])
	if err != nil {
		return errors.New("AcceptInvitation: failed to derive UUID")
	}

	// 3. Fetch from datastore
	curFileList, err := LoadUserFileList(UserFileListAddr, fileListEncKey, fileListHMACKey, true)
	if err != nil {
		return errors.New("AcceptInvitation: failed to load file list")
	}

	//6. Add FileView to FileList, mark recerived
	_, exist = curFileList[filename]
	if exist {
		return errors.New("AcceptInvitation: File already exist")
	} else {
		view.Status = "Received"
		curFileList[filename] = view
	}

	//7. Delete invitation info
	userlib.DatastoreDelete(invitationPtr)

	//8. Get Filemetadata and Verify FileMetadata integrity
	var metadata *FileMetadata
	metadata, err = LoadFileMetadata(view.MetadataUUID, view.EncKey, view.HMACKey)
	if err != nil {
		return errors.New("AcceptInvitation: Failed to load file metadata: " + err.Error())
	}

	// 9. Verify and update SignedShareList
	signedList, err := LoadSignedShareList(metadata.ShareListAddr)
	if err != nil {
		return errors.New("AcceptInvitation: Failed to load share list")
	}
	if signedList.List == nil {
		signedList.List = make(map[string][]ShareEntry)
	}

	// Check for duplicate
	for _, entry := range signedList.List[senderUsername] {
		if entry.Recipient == userdata.Username {
			return errors.New("AcceptInvitation: already shared with this user")
		}
	}

	// 10. Add ShareEntry and store share list
	newEntry := ShareEntry{
		Sender:       senderUsername,
		Recipient:    userdata.Username,
		FileKey:    userdata.FileKey,
		MetadataUUID: view.MetadataUUID,
		Filename:     filename,
	}
	signedList.List[senderUsername] = append(signedList.List[senderUsername], newEntry)

	//store the updated share list
	err = SaveSignedShareList(metadata.ShareListAddr, signedList)
	if err != nil {
		return err
	}

	//11. Store FileMetadata
	err = SaveFileMetadata(view.MetadataUUID, metadata, view.EncKey, view.HMACKey)
	if err != nil {
		return errors.New("AcceptInvitation: Error store UserFileMetadata")
	}
	//12. Store UserFileList
	err = SaveUserFileList(UserFileListAddr, fileListEncKey, fileListHMACKey, curFileList)
	if err != nil {
		return errors.New("AcceptInvitation: Error store UserFileList")
	}
	// fmt.Println("FINISH accept: curFileList:", curFileList)
	return nil
}

// RevokeAccess removes the recipient and all of their downstream shared users from access to the file
func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	//1. Get UserFileList
	userFileListID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "fileList"))[:16])
	if err != nil {
		return errors.New("RevokeAccess: Failed to derive UUID")
	}
	//Derive keys for user’s file list
	fileListEncKey, fileListHMACKey, err := DeriveKeys(userdata.FileKey, []byte("fileListEncKey"), []byte("fileListHMACKey"))
	if err != nil {
		return errors.New("RevokeAccess: Failed to derive file list keys")
	}

	curFileList, err := LoadUserFileList(userFileListID, fileListEncKey, fileListHMACKey, true)
	if err != nil {
		return errors.New("RevokeAccess: Failed to load user file list")
	}

	//2. Check if file exist
	fileView, exist := curFileList[filename]
	if !exist {
		return errors.New("RevokeAccess: File not exist")
	}

	//3. Load and verify FileMetadata
	metadata, err := LoadFileMetadata(fileView.MetadataUUID, fileView.EncKey, fileView.HMACKey)
	if err != nil {
		return errors.New("RevokeAccess: Failed to load file metadata")
	}

	//4. Check if the user is the owner of the file
	if metadata.Owner != userdata.Username {
		return errors.New("RevokeAccess: user is not the owner")
	}

	// Load SignedShareList
	signedList, err := LoadSignedShareList(metadata.ShareListAddr)
	if err != nil {
		return err
	}

	// 确保 List 不为 nil
	if signedList.List == nil {
		signedList.List = make(map[string][]ShareEntry) // 初始化空 map
	}

	// BFS to find users to revoke
	senderEntries, ok := signedList.List[userdata.Username]
	if !ok {
		// 撤回未被接受的邀请
		fileList, err := LoadUserFileList(userFileListID, fileListEncKey, fileListHMACKey, true)
		if err != nil {
			return errors.New("RevokeAccess: Failed to load user file list")
		}

		fileView, ok := fileList[filename]
		if !ok {
			return errors.New("RevokeAccess: File not found in file list")
		}

		invMap := fileView.PendingInv
		if invMap == nil {
			return errors.New("RevokeAccess: No pending invitation map found")
		}

		invID, exists := invMap[recipientUsername]
		if exists {
			userlib.DatastoreDelete(invID)

			delete(invMap, recipientUsername)
			fileView.PendingInv = invMap
			fileView.Status = "Own"
			fileList[filename] = fileView

			err := SaveUserFileList(userFileListID, fileListEncKey, fileListHMACKey, fileList)
			if err != nil {
				return errors.New("RevokeAccess: Failed to save file list after deleting pending invite")
			}

			_, ok := userlib.DatastoreGet(invID)
			if ok {
				userlib.DebugMsg("RevokeAccess Deletion failed: invitation still exists in Datastore!")
			} else {
				userlib.DebugMsg("RevokeAccess Deletion successful: invitation no longer exists.")
			}
			return nil
		}

		return errors.New("RevokeAccess: No share or pending invitation found for this user")
	}

	var originalShare ShareEntry
	found := false
	for _, entry := range senderEntries {
		if entry.Recipient == recipientUsername {
			originalShare = entry
			found = true
			break
		}
	}

	if !found {
		return errors.New("RevokeAccess: Recipient not found in share entries")
	}

	// Step 7: BFS 遍历 ShareList，构造 revokeUsers 和 validUsers 列表
	revokeUsers := make(map[string][]ShareEntry) // 要撤销的用户及其 shareEntry
	remainUsers := make(map[string][]ShareEntry) // 仍然有效的用户及其 shareEntry

	// Step 7.1: 将 originalShare 添加到撤销列表（由 owner → recipient 的那一条）
	revokeUsers[userdata.Username] = []ShareEntry{originalShare}

	// Step 7.2: BFS 队列初始化
	queue := []string{recipientUsername}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		// 遍历 current 用户分享出去的所有记录（即其下游）
		for _, entry := range signedList.List[current] {
			recipient := entry.Recipient

			// 如果 recipient 还未被撤销
			if _, alreadyRevoked := revokeUsers[recipient]; !alreadyRevoked {
				// 标记 sender（current）撤销的分享记录
				revokeUsers[entry.Sender] = append(revokeUsers[entry.Sender], entry)

				// 将 recipient 加入队列，继续扩展
				queue = append(queue, recipient)
			}
		}
	}

	for sender, entries := range signedList.List {
		// Case 1: sender 是当前用户，不能发给 recipientUsername
		if sender == userdata.Username {
			var validEntries []ShareEntry
			for _, entry := range entries {
				if entry.Recipient != recipientUsername {
					validEntries = append(validEntries, entry)
				}
			}
			if len(validEntries) > 0 {
				remainUsers[sender] = validEntries
			}
			continue
		}

		// Case 2: sender 没有被撤销，直接保留
		if _, revoked := revokeUsers[sender]; !revoked {
			remainUsers[sender] = entries
		}
	}

	// 2. 删除所有被撤销用户的 FileView 条目
	for user := range revokeUsers {
		userFileListUUID, _ := uuid.FromBytes(userlib.Hash([]byte(user + "fileList"))[:16])
		userFileListBytes, ok := userlib.DatastoreGet(userFileListUUID)
		if !ok {
			return errors.New("RevokeAccess: UserFileList not exist")
		}
		if len(userFileListBytes) < 64 {
			return errors.New("RevokeAccess: UserFileList length < 64")
		}

		var recipientFileKey []byte
		var recipientFileName string
		for _, entries := range signedList.List {
			for _, e := range entries {
				if e.Recipient == user {
					recipientFileKey = e.FileKey
					recipientFileName = e.Filename
				}
			}
		}
		if recipientFileKey == nil {
			continue
		}
		if recipientFileName == "" {
			continue
		}

		fileListEncKey, fileListHMACKey, err := DeriveKeys(recipientFileKey, []byte("fileListEncKey"), []byte("fileListHMACKey"))
		if err != nil {
			return errors.New("RevokeAccess: Error generate fileListEncKey")
		}

		var fileList map[string]FileView
		fileList, err = LoadUserFileList(userFileListUUID, fileListEncKey, fileListHMACKey, true)
		if err != nil {
			return errors.New("RevokeAccess: Error load UserFileList")
		}

		_, exist = fileList[recipientFileName]

		if !exist {
			return errors.New("RevokeAccess: Revoking File entry not exist")
		}
		delete(fileList, filename)

		// 更新 UserFileList
		err = SaveUserFileList(userFileListUUID, fileListEncKey, fileListHMACKey, fileList)
		if err != nil {
			return errors.New("RevokeAccess: Error save UserFileList")
		}
	}
	// 3. 重新生成文件内容 Chunk
	content, err := userdata.LoadFile(filename)
	if err != nil {
		return errors.New("RevokeAccess: Error loading file content")
	}

	newEncKey, newHMACKey, _ := DeriveKeys(userlib.RandomBytes(16), []byte("fileEncKey"), []byte("fileHMACKey"))

	newHead := uuid.New()
	newTail := uuid.New()
	newChunk := FileChunk{
		Data: content,
		Next: newTail,
	}

	err = SaveFileChunk(newEncKey, newHMACKey, newHead, &newChunk)
	if err != nil {
		return err
	}

	var newSignedList SignedShareList
	// 4. 生成新 ShareList
	if len(remainUsers) == 0 {
		newSignedList = SignedShareList{
			List: make(map[string][]ShareEntry), // 显式初始化
		}
	} else {
		newSignedList = SignedShareList{
			List: remainUsers,
		}
	}

	newShareListAddr := uuid.New()
	err = SaveSignedShareList(newShareListAddr, &newSignedList)
	if err != nil {
		return err
	}

	// 5. 创建新 Metadata
	newMetadata := FileMetadata{
		Owner:         userdata.Username,
		FileName:      filename,
		HeadPtr:       newHead,
		TailPtr:       newTail,
		NumberChunk:   1,
		FileEncKey:    newEncKey,
		HMACKey:       newHMACKey,
		ShareListAddr: newShareListAddr,
		Version:       metadata.Version + 1,
	}
	metadataEncKey, metadataHMACKey, err := DeriveKeys(userlib.RandomBytes(16), []byte("filemetadataEncKey"), []byte("filemetadataHMACKey"))
	if err != nil {
		return err
	}
	newMetadataUUID := uuid.New()

	err = SaveFileMetadata(newMetadataUUID, &newMetadata, metadataEncKey, metadataHMACKey)
	if err != nil {
		return err
	}

	// Update valid users' file list
	for _, entries := range remainUsers {
		for _, e := range entries {
			recipient := e.Recipient
			recipientMasterKey := e.FileKey
			recipientFileName := e.Filename

			fileListEncKey, fileListHMACKey, err := DeriveKeys(recipientMasterKey, []byte("fileListEncKey"), []byte("fileListHMACKey"))
			userListUUID, _ := uuid.FromBytes(userlib.Hash([]byte(recipient + "fileList"))[:16])
			if err != nil {
				return errors.New("RevokeAccess: Error generate UUID")
			}

			var fileList map[string]FileView
			fileList, err = LoadUserFileList(userListUUID, fileListEncKey, fileListHMACKey, true)
			if err != nil {
				return errors.New("RevokeAccess: Error load UserFileList")
			}

			view, exist := fileList[recipientFileName]
			if !exist {
				return errors.New("RevokeAccess: Valid File entry not exist")
			}

			view.MetadataUUID = newMetadataUUID
			view.EncKey = metadataEncKey
			view.HMACKey = metadataHMACKey
			view.Status = "Received"
			fileList[recipientFileName] = view
			fileList[filename] = view

			err = SaveUserFileList(userListUUID, fileListEncKey, fileListHMACKey, fileList)
			if err != nil {
				return errors.New("RevokeAccess: Error save valid user UserFileList")
			}
		}
	}

	// 6. 更新原始拥有者的 FileView
	ownerListUUID, _ := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "fileList"))[:16])
	ownerFileListEncKey, ownerFileListHMACKey, err := DeriveKeys(userdata.FileKey, []byte("fileListEncKey"), []byte("fileListHMACKey"))
	if err != nil {
		return errors.New("RevokeAccess: Failed to derive file list keys")
	}
	var ownerfileList map[string]FileView
	ownerfileList, err = LoadUserFileList(ownerListUUID, ownerFileListEncKey, ownerFileListHMACKey, true)
	if err != nil {
		return errors.New("RevokeAccess: Failed to load owner file list")
	}

	ownerfileList[filename] = FileView{
		MetadataUUID: newMetadataUUID,
		EncKey:       metadataEncKey,
		HMACKey:      metadataHMACKey,
		Status:       "Own",
	}

	// Store updated FileView
	err = SaveUserFileList(ownerListUUID, ownerFileListEncKey, ownerFileListHMACKey, ownerfileList)
	if err != nil {
		return err
	}

	// 7. 删除旧 ShareList、Chunk 链、旧 Metadata
	ptr := metadata.HeadPtr
	for ptr != metadata.TailPtr {
		chunkBytes, ok := userlib.DatastoreGet(ptr)
		if !ok || len(chunkBytes) < 64 {
			break
		}
		var chunk FileChunk
		plain := userlib.SymDec(metadata.FileEncKey, chunkBytes[:len(chunkBytes)-64])
		err := json.Unmarshal(plain, &chunk)
		if err != nil {
			break
		}
		next := chunk.Next
		userlib.DatastoreDelete(ptr)
		ptr = next
	}
	userlib.DatastoreDelete(metadata.TailPtr)
	userlib.DatastoreDelete(metadata.ShareListAddr)
	userlib.DatastoreDelete(fileView.MetadataUUID)

	defer ZeroBytes(newEncKey)
	defer ZeroBytes(newHMACKey)
	defer ZeroBytes(metadataEncKey)
	defer ZeroBytes(metadataHMACKey)
	defer ZeroBytes(fileListEncKey)
	defer ZeroBytes(fileListHMACKey)

	return nil
}
