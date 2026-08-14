package client

// CS161 Project 2 - 撤销访问
// 业务域：知识治理域（撤销 + 前向保密）
// RevokeAccess：BFS 递归撤销下游 + 全密钥重生 + 新 UUID + 重发 FileView
//
// 差异化保留：撤销前向保密——学城生产系统都做不到
// 学城 revoke 命令仅删权限条目，服务端持有明文；本实现密码学层彻底重置

import (
	"encoding/json"
	"errors"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

// RevokeAccess removes the recipient and all of their downstream shared users from access to the file
//
// 流程：
//   1. 加载 owner file list + metadata + signedShareList
//   2. BFS 遍历下游 recipient，构造 revokeUsers / remainUsers
//   3. 删除被撤销用户的 FileView 条目
//   4. 重新生成文件内容 chunk（newEncKey/newHMACKey）
//   5. 创建新 SignedShareList（仅 remainUsers）
//   6. 创建新 FileMetadata（newMetadataUUID + Version+1）
//   7. 更新保留用户的 FileView 指向新 metadata
//   8. 更新 owner 的 FileView
//   9. 删除旧 ShareList、chunk 链、旧 metadata
//
// 前向保密保证：被撤销用户即使保存旧密钥和旧 chunk 副本，也无法解密任何后续数据
func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// 1. Get UserFileList
	userFileListID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "fileList"))[:16])
	if err != nil {
		return errors.New("RevokeAccess: Failed to derive UUID")
	}
	fileListEncKey, fileListHMACKey, err := DeriveKeys(userdata.FileKey, []byte("fileListEncKey"), []byte("fileListHMACKey"))
	if err != nil {
		return errors.New("RevokeAccess: Failed to derive file list keys")
	}

	curFileList, err := LoadUserFileList(userFileListID, fileListEncKey, fileListHMACKey, true)
	if err != nil {
		return errors.New("RevokeAccess: Failed to load user file list")
	}

	// 2. Check if file exist
	fileView, exist := curFileList[filename]
	if !exist {
		return errors.New("RevokeAccess: File not exist")
	}

	// 3. Load and verify FileMetadata
	metadata, err := LoadFileMetadata(fileView.MetadataUUID, fileView.EncKey, fileView.HMACKey)
	if err != nil {
		return errors.New("RevokeAccess: Failed to load file metadata")
	}

	// 4. Check if the user is the owner of the file
	if metadata.Owner != userdata.Username {
		return errors.New("RevokeAccess: user is not the owner")
	}

	// Load SignedShareList
	signedList, err := LoadSignedShareList(metadata.ShareListAddr)
	if err != nil {
		return err
	}

	if signedList.List == nil {
		signedList.List = make(map[string][]ShareEntry)
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
	revokeUsers := make(map[string][]ShareEntry)
	remainUsers := make(map[string][]ShareEntry)

	revokeUsers[userdata.Username] = []ShareEntry{originalShare}

	queue := []string{recipientUsername}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, entry := range signedList.List[current] {
			recipient := entry.Recipient

			if _, alreadyRevoked := revokeUsers[recipient]; !alreadyRevoked {
				revokeUsers[entry.Sender] = append(revokeUsers[entry.Sender], entry)
				queue = append(queue, recipient)
			}
		}
	}

	for sender, entries := range signedList.List {
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

	// 4. 生成新 ShareList
	var newSignedList SignedShareList
	if len(remainUsers) == 0 {
		newSignedList = SignedShareList{
			List: make(map[string][]ShareEntry),
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
