package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	"github.com/google/uuid"
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
	var doris *client.User
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

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
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

			//Overwrite File
			userlib.DebugMsg("Overwriting file data", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			data1, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data1).To(Equal([]byte(contentOne)))

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

			doris, err = client.InitUser("doris", defaultPassword)
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

	Describe("File operations errors tests", func() {

		Specify("Basic Test: Testing InitUser on repeated user names and empty usernames.", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating user Alice clone.")
			_, err = client.InitUser("alice", defaultPassword)
			Expect(err).NotTo(BeNil())

			userlib.DebugMsg("Creating username with empty username")
			bob, err = client.InitUser(emptyString, defaultPassword)
			Expect(err).NotTo(BeNil())

			userlib.DebugMsg("Creating username with non alphanumeric charcter")
			_, err = client.InitUser("#", defaultPassword)
			Expect(err).To(BeNil())

			//case sensitivity
			userlib.DebugMsg("User names are case sensative, Bob and bob are different users")
			aliceLaptop, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err = aliceLaptop.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			alice_file1, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())

			alice_file2, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())

			Expect(alice_file1).NotTo(Equal(alice_file2))

			//User with passord of an empty string
			_, err = client.InitUser("Jack", emptyString)
			Expect(err).To(BeNil())

		})

		Specify("Basic Test: Testing GetUser on non initialized username and if user credentials are invalid", func() {
			userlib.DebugMsg("Getting user when username not intialized")
			alice, err = client.GetUser("chris", defaultPassword)
			Expect(err).NotTo(BeNil())

			userlib.DebugMsg("Getting user when credentials are invalid")
			aliceLaptop, err = client.GetUser("alice", defaultPassword+"hello")
			Expect(err).NotTo(BeNil())

		})

		Specify("Basic Test: Testing GetUser on non initialized username and if user credentials are invalid", func() {
			userlib.DebugMsg("Getting user when username not intialized")
			alice, err = client.GetUser("chis", defaultPassword)
			Expect(err).NotTo(BeNil())

			userlib.DebugMsg("Getting user when credentials are invalid")
			aliceLaptop, err = client.GetUser("alice", defaultPassword+"hello")
			Expect(err).NotTo(BeNil())

		})

		Specify("Basic Test: Testing LoadFile error", func() {
			userlib.DebugMsg("Getting filename when it doesn't exist in user namespace")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			_, err = alice.LoadFile(bobFile)
			Expect(err).NotTo(BeNil())
		})

		Specify("Basic Test: Testing AppendFile errors", func() {
			userlib.DebugMsg("Getting filename when it doesn't exist in user namespace")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).NotTo(BeNil())
		})

		Specify("Basic Test: Testing CreateInvitation errors", func() {
			userlib.DebugMsg("Getting filename when it doesn't exist in user namespace")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob with filename that does not exist.")
			_, err = alice.CreateInvitation(bobFile, "bob")
			Expect(err).NotTo(BeNil())

			userlib.DebugMsg("Creating invitation where username does not exist")
			_, err = alice.CreateInvitation(aliceFile, "eve")
			Expect(err).NotTo(BeNil())

		})

		Specify("Basic Test: Testing Accept invitation errors", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, "File1")
			Expect(err).To(BeNil())

			userlib.DebugMsg("accetpting invitation when user already has a file with chosen filename")
			err = bob.AcceptInvitation("alice", invite, "File1")
			Expect(err).NotTo(BeNil())

			userlib.DebugMsg("invitation pointer is corrupt")
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			invite2, err := bob.CreateInvitation(bobFile, "alice")
			Expect(err).To(BeNil())

			userlib.DatastoreDelete(invite2)

			err = alice.AcceptInvitation("bob", invite2, "File2")
			Expect(err).NotTo(BeNil())

			//Invitation is revoked
			invite3, err := alice.CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Doris's access aliceFile")
			err = alice.RevokeAccess(aliceFile, "doris")
			Expect(err).To(BeNil())

			err = doris.AcceptInvitation("alice", invite3, "File3")
			Expect(err).NotTo(BeNil())

		})

		Specify("Basic Test: Testing Revoke invitation errors", func() {
			userlib.DebugMsg("Getting filename when it doesn't exist in user namespace")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).NotTo(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).NotTo(BeNil())

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, "File1")
			Expect(err).To(BeNil())

		})

	})

	Describe("Basic Tests: Accessing keystore and Datastore", func() {
		Specify("InitUser", func() {
			userlib.DebugMsg("Get user after deleting from Datastore")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			passwordHash := userlib.Argon2Key([]byte(defaultPassword), []byte("alice"), 16)

			username_new, err := userlib.HashKDF(passwordHash, []byte("alice"))
			Expect(err).To(BeNil())

			user_uuid, err := uuid.FromBytes(username_new[:16])
			Expect(err).To(BeNil())

			userlib.DatastoreDelete(user_uuid)

			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).NotTo(BeNil())

		})

		Specify("StoreFile", func() {
			userlib.DebugMsg("Get user after deleting from Datastore")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			//passwordHash := userlib.Argon2Key([]byte(defaultPassword), []byte("alice"), 16)

			//username_new, err := userlib.HashKDF(passwordHash, []byte("alice"))
			//Expect(err).To(BeNil())

			//user_uuid, err := uuid.FromBytes(username_new[:16])
			//Expect(err).To(BeNil())

			//userlib.DatastoreDelete(user_uuid)

			//aliceDesktop, err = client.GetUser("alice", defaultPassword)
			//Expect(err).NotTo(BeNil())

		})

	})
})
