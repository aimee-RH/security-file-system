package client

// Directory 测试用例挂在 TestStepVersionSuite（stepversion_test.go）的 Ginkgo suite 下
// Ginkgo 不支持多次 RunSpecs 调用，所有 Describe 块自动归到同一 suite

import (
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Directory 权限继承", func() {
	var dirID uuid.UUID
	var encKey, hmacKey []byte

	BeforeEach(func() {
		// 生成随机的目录 ID 和密钥
		dirID = uuid.New()
		encKey = []byte("0123456789abcdef") // 16 bytes
		hmacKey = []byte("fedcba9876543210")
	})

	Describe("接缝 1：SaveDirectory / LoadDirectory", func() {
		Specify("保存后能加载回来", func() {
			dir := &Directory{
				Owner:         "alice",
				DirName:       "team-docs",
				InheritParent: true,
				Permissions:   []Permission{},
			}
			err := SaveDirectory(dirID, dir, encKey, hmacKey)
			Expect(err).To(BeNil())

			loaded, err := LoadDirectory(dirID, encKey, hmacKey)
			Expect(err).To(BeNil())
			Expect(loaded.Owner).To(Equal("alice"))
			Expect(loaded.DirName).To(Equal("team-docs"))
			Expect(loaded.InheritParent).To(BeTrue())
		})

		Specify("HMAC 不匹配返回错误", func() {
			dir := &Directory{Owner: "alice", InheritParent: true}
			err := SaveDirectory(dirID, dir, encKey, hmacKey)
			Expect(err).To(BeNil())

			// 用错误的 hmacKey 加载
			wrongHmac := []byte("wrongwrongwrong")
			_, err = LoadDirectory(dirID, encKey, wrongHmac)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("接缝 2：ResolvePermission 递归继承", func() {
		Specify("子目录继承父目录权限", func() {
			// 父目录：alice 可管理
			parentID := uuid.New()
			parent := &Directory{
				Owner:         "alice",
				DirName:       "root",
				InheritParent: true,
				Permissions: []Permission{
					{SubjectType: "user", Subject: "bob", PermLevel: PermEdit},
				},
			}
			Expect(SaveDirectory(parentID, parent, encKey, hmacKey)).To(BeNil())

			// 子目录：InheritParent=true，无显式权限
			child := &Directory{
				Owner:         "alice",
				DirName:       "sub",
				ParentDirID:   &parentID,
				InheritParent: true,
				Permissions:   []Permission{},
			}
			Expect(SaveDirectory(dirID, child, encKey, hmacKey)).To(BeNil())

			// bob 在子目录应继承父目录的 PermEdit
			level, err := ResolvePermission(dirID, encKey, hmacKey, SubjectIdentity{
				Type:    "user",
				Subject: "bob",
			})
			Expect(err).To(BeNil())
			Expect(level).To(Equal(PermEdit))
		})

		Specify("显式权限优先于继承", func() {
			parentID := uuid.New()
			parent := &Directory{
				Owner: "alice",
				Permissions: []Permission{
					{SubjectType: "user", Subject: "bob", PermLevel: PermEdit},
				},
				InheritParent: true,
			}
			Expect(SaveDirectory(parentID, parent, encKey, hmacKey)).To(BeNil())

			// 子目录：显式给 bob 设 PermBrowse
			child := &Directory{
				Owner:         "alice",
				ParentDirID:   &parentID,
				InheritParent: true,
				Permissions: []Permission{
					{SubjectType: "user", Subject: "bob", PermLevel: PermBrowse},
				},
			}
			Expect(SaveDirectory(dirID, child, encKey, hmacKey)).To(BeNil())

			// bob 在子目录应取显式 PermBrowse，不取父目录 PermEdit
			level, _ := ResolvePermission(dirID, encKey, hmacKey, SubjectIdentity{
				Type:    "user",
				Subject: "bob",
			})
			Expect(level).To(Equal(PermBrowse))
		})

		Specify("切断继承后不再向上查", func() {
			parentID := uuid.New()
			parent := &Directory{
				Owner: "alice",
				Permissions: []Permission{
					{SubjectType: "user", Subject: "bob", PermLevel: PermEdit},
				},
				InheritParent: true,
			}
			Expect(SaveDirectory(parentID, parent, encKey, hmacKey)).To(BeNil())

			// 子目录：InheritParent=false（切断）
			child := &Directory{
				Owner:         "alice",
				ParentDirID:   &parentID,
				InheritParent: false, // 切断
				Permissions:   []Permission{},
			}
			Expect(SaveDirectory(dirID, child, encKey, hmacKey)).To(BeNil())

			// bob 在子目录应无权限（不继承）
			level, _ := ResolvePermission(dirID, encKey, hmacKey, SubjectIdentity{
				Type:    "user",
				Subject: "bob",
			})
			Expect(level).To(Equal(0))
		})
	})

	Describe("接缝 3：GrantPermission / RemoveInheritance / RestoreInheritance", func() {
		Specify("GrantPermission 新增权限", func() {
			dir := &Directory{Owner: "alice", InheritParent: true}
			GrantPermission(dir, SubjectIdentity{Type: "user", Subject: "bob"}, PermEdit)
			Expect(dir.Permissions).To(HaveLen(1))
			Expect(dir.Permissions[0].Subject).To(Equal("bob"))
			Expect(dir.Permissions[0].PermLevel).To(Equal(PermEdit))
		})

		Specify("GrantPermission 已有同主体权限时更新而非新增", func() {
			dir := &Directory{
				Owner: "alice",
				Permissions: []Permission{
					{SubjectType: "user", Subject: "bob", PermLevel: PermBrowse},
				},
			}
			GrantPermission(dir, SubjectIdentity{Type: "user", Subject: "bob"}, PermManage)
			Expect(dir.Permissions).To(HaveLen(1)) // 不重复添加
			Expect(dir.Permissions[0].PermLevel).To(Equal(PermManage))
		})

		Specify("RemoveInheritance 切断继承", func() {
			dir := &Directory{Owner: "alice", InheritParent: true}
			RemoveInheritance(dir)
			Expect(dir.InheritParent).To(BeFalse())
		})

		Specify("RestoreInheritance 恢复继承 + 保留显式权限", func() {
			dir := &Directory{
				Owner:         "alice",
				InheritParent: false,
				Permissions: []Permission{
					{SubjectType: "user", Subject: "bob", PermLevel: PermEdit},
				},
			}
			RestoreInheritance(dir, true)
			Expect(dir.InheritParent).To(BeTrue())
			Expect(dir.Permissions).To(HaveLen(1)) // 保留
		})

		Specify("RestoreInheritance 恢复继承 + 清空显式权限", func() {
			dir := &Directory{
				Owner:         "alice",
				InheritParent: false,
				Permissions: []Permission{
					{SubjectType: "user", Subject: "bob", PermLevel: PermEdit},
				},
			}
			RestoreInheritance(dir, false)
			Expect(dir.InheritParent).To(BeTrue())
			Expect(dir.Permissions).To(BeNil()) // 清空
		})
	})
})
