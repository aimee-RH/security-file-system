package client

// CS161 Project 2 - 文件共享
// 业务域：知识反馈域（共享 invitation）
// CreateInvitation / AcceptInvitation：Hybrid encryption + 数字签名

import (
	"encoding/json"
	"errors"
	"fmt"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

// CreateInvitation securely creates an invitation to share a file
func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	// 1: Verify recipient's public key
	recipientPK, ok := userlib.KeystoreGet(recipientUsername + "_PK")
	if !ok {
		return uuid.Nil, errors.New("CreateInvitation: recipient public key not found")
	}

	// 2: Get FileList
	fileListEncKey, fileListHMACKey, err := DeriveKeys(userdata.FileKey, []byte("fileListEncKey"), []byte("fileListHMACKey"))
	if err != nil {
		return uuid.Nil, err
	}
	userFileListID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "fileList"))[:16])
	if err != nil {
		return uuid.Nil, err
	}

	curFileList, err := LoadUserFileList(userFileListID, fileListEncKey, fileListHMACKey, false)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: Failed to load user file list")
	}

	curFv, exist := curFileList[filename]
	if !exist {
		return uuid.Nil, errors.New("CreateInvitation: FileView not exist")
	}

	curFileMetadataUUID := curFv.MetadataUUID
	curFmEncKey := curFv.EncKey
	curFmHMAC := curFv.HMACKey

	// 3: Load and verify FileMetadata
	var metadata *FileMetadata
	metadata, err = LoadFileMetadata(curFileMetadataUUID, curFmEncKey, curFmHMAC)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: Failed to load file metadata: " + err.Error())
	}

	if err := VerifyFileIntegrity(metadata); err != nil {
		return uuid.Nil, err
	}

	// 4: Generate FileView copy for invitation
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

	// 5: Construct and sign invitation with hybrid encryption
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

	// 6: Store invitation and return UUID
	invID := uuid.New()
	if curFv.PendingInv == nil {
		curFv.PendingInv = make(map[string]uuid.UUID)
	}
	curFv.PendingInv[recipientUsername] = invID
	curFileList[filename] = curFv

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
	// 1: Verify sender's signature key
	senderVerifyKey, ok := userlib.KeystoreGet(senderUsername + "_DS")
	if !ok {
		return errors.New("AcceptInvitation: sender's signature key not found")
	}

	// 2: Get and parse invitation
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

	if len(curInv.EncView) == 0 || len(curInv.EncryptedKey) == 0 || len(curInv.SenderSig) == 0 {
		return errors.New("AcceptInvitation: invitation revoked or malformed")
	}

	// 3: Verify EncView signature
	if err := userlib.DSVerify(senderVerifyKey, curInv.EncView, curInv.SenderSig); err != nil {
		return errors.New("AcceptInvitation: invalid invitation signature")
	}

	if curInv.EncryptedKey == nil || curInv.EncView == nil || curInv.SenderSig == nil {
		return errors.New("AcceptInvitation: invalid or revoked invitation data")
	}

	// 4: Decrypt EncView → FileView
	_, viewBytes, err := HybridDecrypt(userdata.PrivateKey, curInv.EncryptedKey, curInv.EncView)
	if err != nil {
		return errors.New("AcceptInvitation: cannot decrypt FileView: " + err.Error())
	}

	var view FileView
	err = json.Unmarshal(viewBytes, &view)
	if err != nil {
		return errors.New("AcceptInvitation: cannot unmarshal FileView")
	}

	// 5: Verify FileView status
	if view.Status != "Share" {
		return errors.New("AcceptInvitation: invalid FileView status")
	}

	// 6: Get file list
	fileListEncKey, fileListHMACKey, err := DeriveKeys(userdata.FileKey, []byte("fileListEncKey"), []byte("fileListHMACKey"))
	if err != nil {
		return errors.New("AcceptInvitation: failed to derive file list keys")
	}

	UserFileListAddr, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "fileList"))[:16])
	if err != nil {
		return errors.New("AcceptInvitation: failed to derive UUID")
	}

	curFileList, err := LoadUserFileList(UserFileListAddr, fileListEncKey, fileListHMACKey, true)
	if err != nil {
		return errors.New("AcceptInvitation: failed to load file list")
	}

	// 7: Add FileView to FileList, mark received
	_, exist = curFileList[filename]
	if exist {
		return errors.New("AcceptInvitation: File already exist")
	}
	view.Status = "Received"
	curFileList[filename] = view

	// 8: Delete invitation info
	userlib.DatastoreDelete(invitationPtr)

	// 9: Get Filemetadata and Verify FileMetadata integrity
	var metadata *FileMetadata
	metadata, err = LoadFileMetadata(view.MetadataUUID, view.EncKey, view.HMACKey)
	if err != nil {
		return errors.New("AcceptInvitation: Failed to load file metadata: " + err.Error())
	}

	// 10: Verify and update SignedShareList
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

	// 11: Add ShareEntry and store share list
	newEntry := ShareEntry{
		Sender:       senderUsername,
		Recipient:    userdata.Username,
		FileKey:      userdata.FileKey,
		MetadataUUID: view.MetadataUUID,
		Filename:     filename,
	}
	signedList.List[senderUsername] = append(signedList.List[senderUsername], newEntry)

	err = SaveSignedShareList(metadata.ShareListAddr, signedList)
	if err != nil {
		return err
	}

	// 12: Store FileMetadata
	err = SaveFileMetadata(view.MetadataUUID, metadata, view.EncKey, view.HMACKey)
	if err != nil {
		return errors.New("AcceptInvitation: Error store UserFileMetadata")
	}
	// 13: Store UserFileList
	err = SaveUserFileList(UserFileListAddr, fileListEncKey, fileListHMACKey, curFileList)
	if err != nil {
		return errors.New("AcceptInvitation: Error store UserFileList")
	}
	return nil
}
