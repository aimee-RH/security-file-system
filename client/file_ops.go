package client

// CS161 Project 2 - 文件操作
// 业务域：知识生产域（文件 CRUD）
// StoreFile / AppendToFile / AppendWithRetry / LoadFile

import (
	"errors"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

// StoreFile 存储文件（新建或覆盖）
func (userdata *User) StoreFile(filename string, data []byte) (err error) {
	userFileListID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "fileList"))[:16])
	if err != nil {
		return err
	}
	fileListEncKey, fileListHMACKey, err := DeriveKeys(userdata.FileKey, []byte("fileListEncKey"), []byte("fileListHMACKey"))
	if err != nil {
		return err
	}

	fileList, err := LoadUserFileList(userFileListID, fileListEncKey, fileListHMACKey, true)
	if err != nil {
		return err
	}
	fileView, exist := fileList[filename]
	chunkCount := 1

	if !exist {
		// 新建文件
		chunkUUID := uuid.New()
		fileMetadataUUID := uuid.New()
		nextchunkUUID := uuid.New()
		ShareListAddr := uuid.New()
		userlib.DebugMsg("StoreFile: chunkUUID: %v\n", chunkUUID)

		fileEncKey, fileHMACKey, err := DeriveKeys(userlib.RandomBytes(16), []byte("fileEncKey"), []byte("fileHMACKey"))
		if err != nil {
			return err
		}

		fileChunk := FileChunk{
			Data: data,
			Next: nextchunkUUID,
		}

		err = SaveFileChunk(fileEncKey, fileHMACKey, chunkUUID, &fileChunk)
		if err != nil {
			return err
		}

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
		// 覆盖已有文件
		fileMetadataUUID := fileView.MetadataUUID
		metadataEncKey := fileView.EncKey
		metadataHMACKey := fileView.HMACKey
		fileMetadata, err := LoadFileMetadata(fileMetadataUUID, metadataEncKey, metadataHMACKey)
		if err != nil {
			return err
		}

		fileEncKey := fileMetadata.FileEncKey
		fileHMACKey := fileMetadata.HMACKey

		// 删除旧 chunk 链
		curChunkUUID := fileMetadata.HeadPtr
		for {
			fileChunk, err := LoadFileChunk(fileEncKey, fileHMACKey, curChunkUUID)
			if err != nil {
				return errors.New("StoreFile: fail to load old file chunk")
			}
			userlib.DatastoreDelete(curChunkUUID)

			if fileChunk.Next == fileMetadata.TailPtr {
				break
			}
			curChunkUUID = fileChunk.Next
		}

		// 创建新 chunk
		newChunkUUID := uuid.New()
		nextchunkUUID := uuid.New()
		newFileChunk := FileChunk{
			Data: data,
			Next: nextchunkUUID,
		}
		userlib.DebugMsg("StoreFile: newChunkUUID: %v\n", newChunkUUID)

		err = SaveFileChunk(fileEncKey, fileHMACKey, newChunkUUID, &newFileChunk)
		if err != nil {
			return err
		}

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

	err = SaveUserFileList(userFileListID, fileListEncKey, fileListHMACKey, fileList)
	if err != nil {
		return err
	}
	defer ZeroBytes(fileListEncKey)
	defer ZeroBytes(fileListHMACKey)

	return nil
}

// AppendToFile 追加数据到文件末尾
// 内部使用 SaveFileMetadataWithVersion 实现乐观锁，冲突时返回 ErrStepVersionConflict
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

	fileMetadataUUID := fileView.MetadataUUID
	metadataEncKey := fileView.EncKey
	metadataHMACKey := fileView.HMACKey

	fileMetadata, err := LoadFileMetadata(fileMetadataUUID, metadataEncKey, metadataHMACKey)
	if err != nil || fileMetadata == nil {
		return errors.New("AppendToFile: Failed to load file metadata")
	}
	fileEncKey := fileMetadata.FileEncKey
	fileHMACKey := fileMetadata.HMACKey

	// chunk层：在原 tail 位置写入新 chunk，新 tail 是预留 UUID
	newChunkUUID := fileMetadata.TailPtr
	newNextChunkUUID := uuid.New()
	fileChunk := FileChunk{
		Data: data,
		Next: newNextChunkUUID,
	}

	err = SaveFileChunk(fileEncKey, fileHMACKey, newChunkUUID, &fileChunk)
	if err != nil {
		return err
	}

	// metadata层：更新 tail + version，带乐观锁保存
	fileMetadata.TailPtr = newNextChunkUUID
	fileMetadata.NumberChunk++
	fileMetadata.Version++

	// 借鉴学城 stepVersion：传入当前版本号，冲突时返回 ErrStepVersionConflict
	err = SaveFileMetadataWithVersion(fileMetadataUUID, fileMetadata, metadataEncKey, metadataHMACKey, fileMetadata.Version-1)
	if err != nil {
		return err
	}

	defer ZeroBytes(metadataEncKey)
	defer ZeroBytes(metadataHMACKey)
	defer ZeroBytes(fileListEncKey)
	defer ZeroBytes(fileListHMACKey)
	return nil
}

// AppendWithRetry 带重试的 append 封装
// ponytail: CS161 不允许 import time，无指数退避；纯循环重试
// 遇到 ErrStepVersionConflict 重新拉取并重试，其他错误直接返回
func (userdata *User) AppendWithRetry(filename string, data []byte, maxRetry int) error {
	if maxRetry < 0 {
		maxRetry = 0
	}
	var lastErr error
	for i := 0; i <= maxRetry; i++ {
		lastErr = userdata.AppendToFile(filename, data)
		if lastErr == nil {
			return nil
		}
		if lastErr != ErrStepVersionConflict {
			return lastErr
		}
		// conflict：下次循环会重新 LoadFileMetadata 拿最新版本
	}
	return errors.New("max retry exceeded")
}

// LoadFile 加载并解密文件
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

	curChunkUUID := fileMetadata.HeadPtr
	for {
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
