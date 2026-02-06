package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.

	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"math/rand"
	_ "strconv"
	_ "strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/google/uuid"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"
const AESKeySizeBytes = 16
const AESBlockSizeBytes = 16

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!

	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Security: Filename length should be obfuscated", func() {
			alice, _ = client.InitUser("alice", defaultPassword)
			
			// 存储超短文件名
			userlib.DatastoreResetBandwidth()
			alice.StoreFile("a", []byte("content"))
			shortNameBW := userlib.DatastoreGetBandwidth()

			// 存储超长文件名
			userlib.DatastoreResetBandwidth()
			alice.StoreFile("this_is_a_very_long_filename_that_should_be_hidden", []byte("content"))
			longNameBW := userlib.DatastoreGetBandwidth()

			// 两者的带宽消耗应该完全一致（或极其接近）
			Expect(shortNameBW).To(Equal(longNameBW), "Bandwidth reveals filename length!")
		})

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			Expect(aliceLaptop.Username).To(Equal("alice")) // or any other property/method
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			// _, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("InitUser Tests", func() {

		Specify("InitUser Tests: initialize a new user", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil(), "Failed to init user Alice")
			Expect(alice).NotTo(BeNil(), "User Alice should not be nil")
		})

		Specify("InitUser Tests: return an error if the username is empty", func() {
			// 输入的用户名为空
			userlib.DebugMsg("Initializing with empty username.")
			_, err = client.InitUser("", defaultPassword)
			Expect(err).NotTo(BeNil(), "Expected an error for empty username")
			// Expect(err.Error()).To(ContainSubstring("username cannot be empty"), "Error message should indicate empty username")
		})

		Specify("InitUser Tests: return an error if the user already exists", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil(), "Failed to init user Alice")

			// 用户名已存在
			userlib.DebugMsg("Initializing again with username Alice.")
			_, err = client.InitUser("alice", defaultPassword)
			Expect(err).NotTo(BeNil(), "Expected an error for duplicate user")
			// Expect(err.Error()).To(ContainSubstring("user already exists"), "Error message should indicate duplicate user")
		})

	})

	Describe("GetUser Tests", func() {

		// 输出的用户数据是否正确
		Specify("GetUser Tests: retrieve an existing user", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil(), "Failed to init user Alice")

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil(), "Failed to retrieve user Alice")
			Expect(aliceLaptop).NotTo(BeNil(), "Retrieved user should not be nil")
			Expect(aliceLaptop.Username).To(Equal("alice"), "Retrieved user should have the correct username")
		})

		// 用户不存在
		Specify("GetUser Tests: return an error if the user does not exist", func() {
			userlib.DebugMsg("Getting user Bob.")
			_, err = client.GetUser("bob", defaultPassword)
			Expect(err).NotTo(BeNil(), "Expected an error for non-existent user")
			// Expect(err.Error()).To(ContainSubstring("user not found"), "Error message should indicate user not found")
		})

		// 密码错误
		Specify("GetUser Tests: return an error if the password is incorrect", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil(), "Failed to init user Alice")

			_, err = client.GetUser("alice", "wrongpassword")
			Expect(err).NotTo(BeNil(), "Expected an error for incorrect password")
			// Expect(err.Error()).To(ContainSubstring("incorrect password"), "Error message should indicate incorrect password")
		})

		// 输入的用户名为空
		Specify("GetUser Tests: return an error if the username is empty", func() {
			userlib.DebugMsg("Input empty username.")
			_, err = client.GetUser("", defaultPassword)
			Expect(err).NotTo(BeNil(), "Expected an error for empty username")
			// Expect(err.Error()).To(ContainSubstring("username cannot be empty"), "Error message should indicate empty username")
		})

	})

	Describe("MultiDevice Tests(6/6)", func() {
		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		// 1. 数据不同步(当用户在一台设备上更新文件后，另一台设备无法立即看到最新数据)
		Specify("Multiple devices should see latest file updates", func() {
			userlib.DebugMsg("Initializing user Alice.")
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil(), "Failed to init user Alice")

			userlib.DebugMsg("Retrieving user Alice on another device.")
			aliceLaptop, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil(), "Failed to retrieve user Alice on laptop")

			alicePhone, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil(), "Failed to retrieve user Alice on phone")

			// 电脑上存储文件
			userlib.DebugMsg("Alice stores a file on laptop.")
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil(), "Failed to store file on laptop")

			// 手机上加载文件
			userlib.DebugMsg("Alice loads the file on phone.")
			data, err := alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil(), "Failed to load file on phone")
			Expect(data).To(Equal([]byte(contentOne)), "Phone should see latest file update")

			// 手机上追加内容
			userlib.DebugMsg("Alice appends content to file on phone.")
			err = alicePhone.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil(), "Failed to append file on phone")

			// 电脑上加载更新后的文件
			userlib.DebugMsg("Alice loads the file on laptop.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil(), "Failed to load file on laptop")
			Expect(data).To(Equal([]byte(contentOne+contentTwo)), "Laptop should see appended content from phone")
		})

		// 2. 并发冲突(两个设备同时修改文件)
		Specify("Concurrent modifications should not cause data loss", func() {
			userlib.DebugMsg("Initializing user Alice.")
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil(), "Failed to init user Alice")

			userlib.DebugMsg("Retrieving user Alice on another device.")
			aliceLaptop, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil(), "Failed to retrieve user Alice on laptop")

			alicePhone, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil(), "Failed to retrieve user Alice on phone")

			// 电脑上存储文件
			userlib.DebugMsg("Alice stores a file on laptop.")
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil(), "Failed to store file on laptop")

			//两个设备同时追加同一文件
			userlib.DebugMsg("Both devices append to the same file concurrently.")
			err = aliceLaptop.AppendToFile(aliceFile, []byte(contentOne))
			err = alicePhone.AppendToFile(aliceFile, []byte(contentTwo))

			// 等待 100ms 确保并发执行
			time.Sleep(100 * time.Millisecond)

			userlib.DebugMsg("Alice loads the file on laptop.")
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil(), "Failed to load file after concurrent updates")
			Expect(data).To(ContainSubstring(contentOne), "Laptop's update is missing")
			Expect(data).To(ContainSubstring(contentTwo), "Phone's update is missing")

			userlib.DebugMsg("Alice loads the file on phone.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil(), "Failed to load file after concurrent updates")
			Expect(data).To(ContainSubstring(contentOne), "Laptop's update is missing")
			Expect(data).To(ContainSubstring(contentTwo), "Phone's update is missing")
		})

		// 3. 设备缓存问题
		Specify("Devices should not use outdated cached data", func() {
			userlib.DebugMsg("Initializing user Alice.")
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil(), "Failed to init user Alice")

			userlib.DebugMsg("Retrieving user Alice on another device.")
			aliceLaptop, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil(), "Failed to retrieve user Alice on laptop")

			alicePhone, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil(), "Failed to retrieve user Alice on phone")

			// 电脑上存储文件
			userlib.DebugMsg("Alice stores a file on laptop.")
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil(), "Failed to store file on laptop")

			// 手机上加载文件
			userlib.DebugMsg("Alice loads the file on phone.")
			data, err := alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil(), "Failed to load file on phone")
			Expect(data).To(Equal([]byte(contentOne)), "Phone should see latest file update")

			// 电脑上存储文件
			userlib.DebugMsg("Alice change the file on laptop.")
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil(), "Failed to stores file on laptop")

			// 确保手机读取到的是最新值
			userlib.DebugMsg("Alice loads the file on laptop.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil(), "Failed to load updated file")
			Expect(data).To(Equal([]byte(contentTwo)), "Phone loaded outdated cached data")
		})

		// 4. 断网后的数据一致性
		Specify("Offline edits should merge correctly after reconnecting", func() {
			userlib.DebugMsg("Initializing user Alice.")
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil(), "Failed to init user Alice")

			userlib.DebugMsg("Retrieving user Alice on another device.")
			aliceLaptop, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil(), "Failed to retrieve user Alice on laptop")

			alicePhone, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil(), "Failed to retrieve user Alice on phone")

			// 电脑上存储文件
			userlib.DebugMsg("Alice stores a file on laptop.")
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil(), "Failed to store file on laptop")

			// 手机上加载文件
			userlib.DebugMsg("Alice loads the file on phone.")
			data, err := alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil(), "Failed to load file on phone")
			Expect(data).To(Equal([]byte(contentOne)), "Phone should see latest file update")

			// 模拟断网并修改
			userlib.DebugMsg("Alice change the file on laptop.")
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil(), "Failed to store offline edit on laptop")

			userlib.DebugMsg("Alice append the file on phone.")
			alicePhone.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil(), "Failed to append offline edit on phone")

			// 重新同步
			content, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil(), "Failed to load after reconnection")
			userlib.DebugMsg("data: %s", content)
			Expect(content).To(SatisfyAny(
				Equal([]byte(contentTwo+contentThree)),
				Equal([]byte(contentThree+contentTwo)),
			), "Offline edits not merged correctly")
		})

		// 5. 多次登录后的数据完整性
		Specify("Logging in from multiple devices should retain data", func() {
			userlib.DebugMsg("Initializing user Alice.")
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil(), "Failed to init user Alice")

			userlib.DebugMsg("Retrieving user Alice.")
			aliceLaptop, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil(), "Failed to retrieve user Alice on laptop")

			userlib.DebugMsg("Alice stores a file on laptop.")
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil(), "Failed to store file on laptop")

			// 重新登录
			aliceLaptop, _ = client.GetUser("alice", defaultPassword)
			err = aliceLaptop.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil(), "Failed to append file after relogin")

			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil(), "Failed to load session file")
			Expect(data).To(Equal([]byte(contentOne+contentTwo)), "Session data lost after relogin")
		})

	})

	Describe("AppendToFile Efficiency Tests(0/3)", func() {
		BeforeEach(func() {
			userlib.DebugMsg("Running BeforeEach...")
			userlib.DatastoreClear()
			userlib.DatastoreResetBandwidth()
			// 添加延迟确保清除完成
			time.Sleep(100 * time.Millisecond)

			alice, err = client.InitUser("alice", defaultPassword)
			// userlib.DebugMsg("InitUser result: %v, error: %v\n", alice, err)
			Expect(err).To(BeNil())
		})

		Specify("success - Appending small data should use minimal bandwidth", func() {
			// 存储初始文件内容
			userlib.DebugMsg("Storing initial file 'testfile' with content 'Hello'.")
			err = alice.StoreFile("testfile", []byte("Hello"))
			Expect(err).To(BeNil())

			appendContent1 := []byte(" World")

			// 第一次追加小数据
			before1 := userlib.DatastoreGetBandwidth()
			userlib.DebugMsg("Appending ' World' to 'testfile'.")
			err = alice.AppendToFile("testfile", appendContent1)
			Expect(err).To(BeNil())

			finalBandwidth1 := userlib.DatastoreGetBandwidth()
			bandwidthUsed1 := finalBandwidth1 - before1

			// 验证带宽使用仅与追加数据大小成比例
			userlib.DebugMsg("Bandwidth used for append: %d bytes.", bandwidthUsed1)
			Expect(bandwidthUsed1).To(BeNumerically("<=", len(appendContent1)+3000)) // 允许一个小的常数开销
		})

		Specify("success - Appending large data should use bandwidth proportional to append size", func() {
			// 存储初始文件内容
			userlib.DebugMsg("Storing initial file 'largefile' with content 'Start'.")
			err = alice.StoreFile("largefile", []byte("Start"))
			Expect(err).To(BeNil())

			// 记录追加操作前的带宽使用情况
			initialBandwidth := userlib.DatastoreGetBandwidth()

			// 定义两个不同大小的追加数据
			smallAppendContent := make([]byte, 1*1024*1024)  // 1MB
			largeAppendContent := make([]byte, 10*1024*1024) // 10MB

			// 记录第一次追加（小文件）的带宽使用
			userlib.DebugMsg("Appending 1MB of data to 'largefile'.")
			err = alice.AppendToFile("largefile", smallAppendContent)
			Expect(err).To(BeNil())
			bandwidthSmall := userlib.DatastoreGetBandwidth() - initialBandwidth

			// 追加大数据
			beforeLarge := userlib.DatastoreGetBandwidth() // 重新获取追加前的带宽
			userlib.DebugMsg("Appending 10MB of data to 'largefile'.")
			err = alice.AppendToFile("largefile", largeAppendContent)
			Expect(err).To(BeNil())
			bandwidthLarge := userlib.DatastoreGetBandwidth() - beforeLarge

			// // 验证带宽使用仅与追加数据大小成比例
			// userlib.DebugMsg("Bandwidth used for large append: %d bytes.", bandwidthSmall)
			// Expect(bandwidthUsed).To(BeNumerically("<=", len(largeAppendContent)+3000)) // 允许一个小的常数开销

			// 验证比例关系：bandwidthLarge / bandwidthSmall ≈ 10MB / 1MB = 10
			ratio := float64(bandwidthLarge) / float64(bandwidthSmall)
			expectedRatio := float64(len(largeAppendContent)) / float64(len(smallAppendContent))

			userlib.DebugMsg("Bandwidth ratio (large/small): %.2f (expected ≈ %.2f)", ratio, expectedRatio)
			Expect(ratio).To(BeNumerically("~", expectedRatio, 0.1)) // 允许10%误差
		})

		Specify("success - Multiple small appends should not cause increasing bandwidth usage", func() {
			// 存储初始文件内容
			userlib.DebugMsg("Storing initial file 'multitest' with content 'Init'.")
			err = alice.StoreFile("multitest", []byte("Init"))
			Expect(err).To(BeNil())

			// 定义要追加的小数据块
			appendContent := []byte("A")
			numAppends := 100
			lastbandwidth := 0
			bandwidthUsed := 0

			for i := 0; i < numAppends; i++ {
				// 记录每次追加操作前的带宽使用情况
				initialBandwidth := userlib.DatastoreGetBandwidth()

				// 追加小数据
				userlib.DebugMsg("Appending 'A' to 'multitest', iteration %d.", i+1)
				err = alice.AppendToFile("multitest", appendContent)
				Expect(err).To(BeNil())

				// 计算追加操作后的带宽使用情况
				finalBandwidth := userlib.DatastoreGetBandwidth()
				bandwidthUsed = finalBandwidth - initialBandwidth

				if i != 0 {
					// 验证每次追加的带宽使用保持一致
					userlib.DebugMsg("Bandwidth used for append %d: %d bytes.", i+1, bandwidthUsed)
					Expect(lastbandwidth).To(BeNumerically("~", bandwidthUsed, 100))
				}

				lastbandwidth = bandwidthUsed
			}
		})
	})
	Describe("Namespacing Tests(1/3)", func() {

		BeforeEach(func() {
			// 初始化用户Alice
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// 初始化用户Bob
			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// 确保数据存储在每个测试前被清空
			userlib.DatastoreClear()
		})

		Specify("1- Different users can have files with the same name without conflict", func() {
			// Alice存储名为"shared.txt"的文件
			userlib.DebugMsg("Alice stores a file named 'shared.txt' with content 'Alice's content'.")
			err = alice.StoreFile("shared.txt", []byte("Alice's content"))
			Expect(err).To(BeNil())

			// Bob存储同名文件"shared.txt"
			userlib.DebugMsg("Bob stores a file named 'shared.txt' with content 'Bob's content'.")
			err = bob.StoreFile("shared.txt", []byte("Bob's content"))
			Expect(err).To(BeNil())

			// 验证Alice的文件内容
			userlib.DebugMsg("Alice loads 'shared.txt' and expects to see her own content.")
			content, err := alice.LoadFile("shared.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("Alice's content")))

			// 验证Bob的文件内容
			userlib.DebugMsg("Bob loads 'shared.txt' and expects to see his own content.")
			content, err = bob.LoadFile("shared.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("Bob's content")))
		})

		Specify("2- Overwriting a file does not affect other users' files with the same name", func() {
			// Alice存储名为"notes.txt"的文件
			userlib.DebugMsg("Alice stores a file named 'notes.txt' with content 'Initial notes'.")
			err = alice.StoreFile("notes.txt", []byte("Initial notes"))
			Expect(err).To(BeNil())

			// Bob存储同名文件"notes.txt"
			userlib.DebugMsg("Bob stores a file named 'notes.txt' with content 'Bob's notes'.")
			err = bob.StoreFile("notes.txt", []byte("Bob's notes"))
			Expect(err).To(BeNil())

			// Alice覆盖她的"notes.txt"文件
			userlib.DebugMsg("Alice overwrites 'notes.txt' with new content 'Updated notes'.")
			err = alice.StoreFile("notes.txt", []byte("Updated notes"))
			Expect(err).To(BeNil())

			// 验证Alice的文件内容
			userlib.DebugMsg("Alice loads 'notes.txt' and expects to see 'Updated notes'.")
			content, err := alice.LoadFile("notes.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("Updated notes")))

			// 验证Bob的文件内容未受影响
			userlib.DebugMsg("Bob loads 'notes.txt' and expects to see his original content 'Bob's notes'.")
			content, err = bob.LoadFile("notes.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("Bob's notes")))
		})

		Specify("3- failed -Appending to a file does not affect other users' files with the same name", func() {
			// Alice存储名为"diary.txt"的文件
			userlib.DebugMsg("Alice stores a file named 'diary.txt' with content 'Day 1: Sunny'.")
			err = alice.StoreFile("diary.txt", []byte("Day 1: Sunny"))
			Expect(err).To(BeNil())

			// Bob存储同名文件"diary.txt"
			userlib.DebugMsg("Bob stores a file named 'diary.txt' with content 'Entry 1: Work'.")
			err = bob.StoreFile("diary.txt", []byte("Entry 1: Work"))
			Expect(err).To(BeNil())

			// Alice追加内容到她的"diary.txt"文件
			userlib.DebugMsg("Alice appends ' Day 2: Rainy' to her 'diary.txt'.")
			err = alice.AppendToFile("diary.txt", []byte(" Day 2: Rainy"))
			Expect(err).To(BeNil())

			// 验证Alice的文件内容
			userlib.DebugMsg("Alice loads 'diary.txt' and expects to see 'Day 1: Sunny Day 2: Rainy'.")
			content, err := alice.LoadFile("diary.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("Day 1: Sunny Day 2: Rainy")))

			// 验证Bob的文件内容未受影响
			userlib.DebugMsg("Bob loads 'diary.txt' and expects to see his original content 'Entry 1: Work'.")
			content, err = bob.LoadFile("diary.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("Entry 1: Work")))
		})
	})

	Describe("File Operations Tests(2/5)", func() {
		BeforeEach(func() {
			userlib.DebugMsg("Running BeforeEach...")
			userlib.DatastoreClear()
			// 添加延迟确保清除完成
			time.Sleep(100 * time.Millisecond)
		})

		Specify("1- StoreFile creates a new file and LoadFile retrieves its content", func() {
			// 初始化用户Alice
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			// Alice存储名为"document.txt"的文件
			userlib.DebugMsg("Alice stores a file named 'document.txt' with content 'Hello, World!'.")
			err = alice.StoreFile("document.txt", []byte("Hello, World!"))
			Expect(err).To(BeNil())

			// 验证Alice的文件内容
			userlib.DebugMsg("Alice loads 'document.txt' and expects to see 'Hello, World!'.")
			content, err := alice.LoadFile("document.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("Hello, World!")))
		})

		Specify("2- StoreFile overwrites existing file content", func() {
			// Alice存储名为"notes.txt"的文件
			// 初始化用户Alice
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Alice stores a file named 'notes.txt' with content 'Initial content'.")
			err = alice.StoreFile("notes.txt", []byte("Initial content"))
			Expect(err).To(BeNil())

			// Alice覆盖"notes.txt"的内容
			userlib.DebugMsg("Alice overwrites 'notes.txt' with new content 'Updated content'.")
			err = alice.StoreFile("notes.txt", []byte("Updated content"))
			Expect(err).To(BeNil())

			// 验证Alice的文件内容
			userlib.DebugMsg("Alice loads 'notes.txt' and expects to see 'Updated content'.")
			content, err := alice.LoadFile("notes.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("Updated content")))
		})

		Specify("3- LoadFile returns an error for non-existent files", func() {
			// 尝试加载不存在的文件
			// 初始化用户Alice
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Alice attempts to load 'missing.txt' and expects an error.")
			content, err := alice.LoadFile("missing.txt")
			Expect(err).ToNot(BeNil())
			Expect(content).To(BeNil())
		})

		Specify("4-failed AppendToFile adds content to the end of an existing file", func() {
			// 初始化用户Alice
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			// Alice存储名为"journal.txt"的文件
			userlib.DebugMsg("Alice stores a file named 'journal.txt' with content 'Day 1: Sunny'.")
			err = alice.StoreFile("journal.txt", []byte("Day 1: Sunny"))
			Expect(err).To(BeNil())

			// Alice追加内容到"journal.txt"
			userlib.DebugMsg("Alice appends ' Day 2: Rainy' to 'journal.txt'.")
			err = alice.AppendToFile("journal.txt", []byte(" Day 2: Rainy"))
			Expect(err).To(BeNil())

			// 验证Alice的文件内容
			userlib.DebugMsg("Alice loads 'journal.txt' and expects to see 'Day 1: Sunny Day 2: Rainy'.")
			content, err := alice.LoadFile("journal.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("Day 1: Sunny Day 2: Rainy")))
		})

		Specify("5-failed AppendToFile returns an error when the file does not exist", func() {
			// 初始化用户Alice
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			// 尝试向不存在的文件追加内容
			userlib.DebugMsg("Alice attempts to append to 'nonexistent.txt' and expects an error.")
			err = alice.AppendToFile("nonexistent.txt", []byte("Some content"))
			Expect(err).ToNot(BeNil())
		})
		Specify("6-bigFile", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice2", defaultPassword)
			Expect(err).To(BeNil())
			alice.StoreFile("aliceFile", userlib.RandomBytes(10000))
			alice.AppendToFile("aliceFile", userlib.RandomBytes(10000))

			file, err1 := alice.LoadFile("aliceFile")
			userlib.DebugMsg("file1:\n", file)
			Expect(err).To(BeNil())
			userlib.DebugMsg("err1:\n", err1)

			err2 := alice.AppendToFile("aliceFile", userlib.RandomBytes(10000))
			userlib.DebugMsg("err2:\n", err2)
			Expect(err).To(BeNil())
		})
	})

	Describe("File Sharing Tests(5/5)", func() {

		Specify("1-Test: Comprehensive Create/Accept Invitation Test with Integrity Check", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			// Step 1: Alice 存储数据
			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// Step 2: Alice 创建邀请给 Bob
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			// Step 3: Bob 接受邀请并给出新文件名
			userlib.DebugMsg("Bob accepting invitation with filename %s", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			// Step 4: 验证 Bob 的数据是否与 Alice 一致
			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			// Step 5: Alice 追加新数据
			userlib.DebugMsg("Alice appending data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			// Step 6: 验证 Bob 的数据是否自动更新
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			// Step 7: Bob 创建邀请给 charles
			inviteForCharles, err := bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			// Step 8: charles 接受邀请
			err = charles.AcceptInvitation("bob", inviteForCharles, charlesFile)
			Expect(err).To(BeNil())

			// Step 9: 验证 charles 也能看到最新数据
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			// Step 10: Alice 再次追加数据，确保 charles /Bob 均可查看
			userlib.DebugMsg("Alice appending final content: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			// Step 11: 验证 Bob/Charlie 均能查看到最终数据
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			// Step 12: 检查无效邀请 (恶意伪造的 invitationPtr)
			fakeInvite := uuid.New()
			err = charles.AcceptInvitation("alice", fakeInvite, "fakeFile")
			Expect(err).ToNot(BeNil()) // 错误预期

			// Step 13: 检查已撤销的邀请
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil()) // Bob 应该失去访问权限

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil()) // Charlie 也应失去访问权限
		})

		// Specify("4-Security Test: Prevent Circular Sharing", func() {
		// 	alice, err := client.InitUser("alice", defaultPassword)
		// 	Expect(err).To(BeNil())

		// 	bob, err := client.InitUser("bob", defaultPassword)
		// 	Expect(err).To(BeNil())

		// 	// Step 1: Alice 创建并存储文件
		// 	err = alice.StoreFile("file.txt", []byte("Circular Sharing Test"))
		// 	Expect(err).To(BeNil())

		// 	// Step 2: Alice 创建邀请并分享给 Bob
		// 	inviteBob, err := alice.CreateInvitation("file.txt", "bob")
		// 	Expect(err).To(BeNil())
		// 	err = bob.AcceptInvitation("alice", inviteBob, bobFile)
		// 	Expect(err).To(BeNil())

		// 	// Step 3: Bob 尝试将该文件再次分享回 Alice
		// 	_, err = bob.CreateInvitation(bobFile, "alice")

		// 	// Step 4: 验证系统拒绝循环分享
		// 	Expect(err).ToNot(BeNil()) // 应失败
		// })

		Specify("6-Stress Test: Large File Handling", func() {
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err := client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// Step 1: 创建一个 5MB 的大文件并随机填充数据
			largeData := make([]byte, 5*1024*1024) // 5MB
			_, err = rand.Read(largeData)          // 使用随机数据来模拟真实大文件
			Expect(err).To(BeNil())

			// Step 2: Alice 存储超大文件
			userlib.DebugMsg("[Step 2] Alice storing large file (5MB)")
			err = alice.StoreFile("largeFile.txt", largeData)
			Expect(err).To(BeNil())

			// Step 3: 验证 Alice 是否可以成功加载该超大文件
			userlib.DebugMsg("[Step 3] Alice loading large file (5MB)")
			loadedData, err := alice.LoadFile("largeFile.txt")
			Expect(err).To(BeNil())
			Expect(loadedData).To(Equal(largeData)) // 数据完整性检查

			// Step 4: Alice 创建邀请并分享给 Bob
			inviteBob, err := alice.CreateInvitation("largeFile.txt", "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", inviteBob, "bobLargeFile.txt")
			Expect(err).To(BeNil())

			// Step 5: 验证 Bob 能够正确加载共享的超大文件
			userlib.DebugMsg("[Step 5] Bob loading shared large file (5MB)")
			sharedData, err := bob.LoadFile("bobLargeFile.txt")
			Expect(err).To(BeNil())
			Expect(sharedData).To(Equal(largeData)) // 数据完整性检查

			// Step 6: Bob 向文件追加更多数据
			additionalData := []byte(" - Bob's Contribution")
			err = bob.AppendToFile("bobLargeFile.txt", additionalData)
			Expect(err).To(BeNil())

			// Step 7: Alice 验证文件已正确追加
			finalData := append(largeData, additionalData...)
			loadedData, err = alice.LoadFile("largeFile.txt")
			Expect(err).To(BeNil())
			Expect(loadedData).To(Equal(finalData)) // 确保完整性

			// Step 8: Alice 撤销 Bob 的访问权限
			err = alice.RevokeAccess("largeFile.txt", "bob")
			Expect(err).To(BeNil())

			// Step 9: Bob 尝试再次访问应失败
			_, err = bob.LoadFile("bobLargeFile.txt")
			Expect(err).ToNot(BeNil()) // Bob 的访问应被拒绝
		})

	})

	Describe("RevokeAccess Tests(3/4)", func() {

		Specify("7.1 - Replay of Old Invitation Should Fail", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte("top secret"))
			Expect(err).To(BeNil())

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, "replayed")
			Expect(err).ToNot(BeNil())
		})
		Specify("7.5 - Revoke Subtree Recursively", func() {
			alice, _ = client.InitUser("alice", defaultPassword)
			bob, _ = client.InitUser("bob", defaultPassword)
			charles, _ = client.InitUser("charles", defaultPassword)

			_ = alice.StoreFile(aliceFile, []byte("secret"))
			inviteBob, _ := alice.CreateInvitation(aliceFile, "bob")
			_ = bob.AcceptInvitation("alice", inviteBob, bobFile)

			inviteDave, _ := bob.CreateInvitation(bobFile, "charles")
			_ = charles.AcceptInvitation("bob", inviteDave, charlesFile)

			_ = alice.RevokeAccess(aliceFile, "bob")

			_, err := charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())
		})
		Specify("7.6 - Non-Revoked User Access Unaffected", func() {
			alice, _ = client.InitUser("alice", defaultPassword)
			userlib.DebugMsg("Initializing user Alice.")
			bob, _ = client.InitUser("bob", defaultPassword)
			charles, _ = client.InitUser("charles", defaultPassword)

			_ = alice.StoreFile(aliceFile, []byte("stable"))
			inviteBob, _ := alice.CreateInvitation(aliceFile, "bob")
			_ = bob.AcceptInvitation("alice", inviteBob, bobFile)

			inviteCharlie, _ := alice.CreateInvitation(aliceFile, "charles")
			_ = charles.AcceptInvitation("alice", inviteCharlie, charlesFile)

			userlib.DebugMsg("charlesFile before revoke:", charlesFile)

			_ = alice.RevokeAccess(aliceFile, "bob")
			data, err := charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("stable")))
		})

		Specify("7.8 - Revoked User Cannot Create New Invitations", func() {
			// 初始化用户
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err := client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// Alice 存储文件并分享给 Bob
			err = alice.StoreFile("file.txt", []byte("Content"))
			Expect(err).To(BeNil())
			inviteBob, err := alice.CreateInvitation("file.txt", "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", inviteBob, bobFile)
			Expect(err).To(BeNil())

			// Alice 撤销 Bob 的访问权限
			err = alice.RevokeAccess("file.txt", "bob")
			Expect(err).To(BeNil())

			// 验证 Bob 无法创建新的邀请
			_, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).ToNot(BeNil())
		})

		Specify("7.9 - Test pendingInv not influence revoke", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

		})

		Specify("7.10 - Revoke before accept invitation", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s.", aliceFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			// alice 在bob接受邀请之前就撤销了bob的访问权限
			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			//bob自己调用storefile创建的一个在自己namespace的文件 和 alice无关
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			var aliceData, bobData []byte
			bobData, err = bob.LoadFile(bobFile)
			if err == nil {
				Expect(bobData).To(Equal([]byte(contentTwo)))
				Expect(bobData).ToNot(Equal(aliceData))
				userlib.DebugMsg("Bob's file is not the same as Alice's file.")

			}
		})
		
		// Specify("7.7 - UUID Guessing Should Fail", func() {
		// 	alice, _ = client.InitUser("alice", defaultPassword)
		// 	bob, _ = client.InitUser("bob", defaultPassword)

		// 	_ = alice.StoreFile(aliceFile, []byte("hidden"))
		// 	invite, _ := alice.CreateInvitation(aliceFile, "bob")
		// 	_ = bob.AcceptInvitation("alice", invite, bobFile)

		// 	_ = alice.RevokeAccess(aliceFile, "bob")

		// 	guesses := attackerGuessChunkUUIDs()
		// 	for _, guess := range guesses {
		// 		data := attackerTryReadChunk(guess)
		// 		Expect(data).To(BeNil())
		// 	}
		// })
	})
})
