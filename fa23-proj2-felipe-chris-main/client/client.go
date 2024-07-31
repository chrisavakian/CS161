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

type FileLibrary struct {
	File        map[string]uuid.UUID   //Stores filenames with the UUID for their fileUnlock
	FilesSender map[string]string      //Store filenames with the name of the sender that sent it (if user is the same as sender, then they are the owner)
	FilesShared map[string][]uuid.UUID //Stores a filename with an ARRAY of all the Intermediate_Outside Structs that have been made for that file
}

type FileLibraryOutside struct {
	FileLibrary      []byte //Encrypted with SymENC with MasterKey
	FileLibrary_Hash []byte //HMAC with Masterkey
}

type User struct {
	Username string
	Password []byte //Note this is argon2key-ed
	DS_SK    userlib.DSSignKey
	RSA_SK   userlib.PKEDecKey
}

type UserOutside struct {
	User      []byte //Encrypted with SymEnc of UserKey (derived from Password)
	User_Hash []byte //Hmaced with UserHMAC (Derived from password)
}

type File struct {
	NumOfAppendsENC     []byte //Encrypted with Masterkey, it is an int
	NumOfAppendsEncHash []byte //HMAC with Masterkey
}

type Intermediate struct {
	FileUUID  uuid.UUID //Stores the UUID of the file's File struct
	MasterKey []byte    //Stores the masterkey of the file
	Recipient string    //Stores who this intermediate struct belongs to
}

type Intermediate_Outside struct {
	Intermediate_ENC      []byte //Encrypted with the Unlock_Key
	Intermediate_ENC_Hash []byte //HMACed with teh Unlock_Key
}

type FileUnlock struct {
	IntermediateUUID_ENC      []byte //Stores the uuid.UUID of the Intermediate_Outside struct associated with that file Encrypte with UnlockKey
	IntermediateUUID_ENC_Hash []byte //HMAC with UnlockKEy
	UnlockKey_ENC             []byte //RSA Encrypted
	UnlockKey_ENC_Hash        []byte //Digitally Signed by Sender
}

type FileContent struct {
	Content_ENC      []byte //This is where the actual content of the file is stored, ecnrypted witgh masterkye
	Content_ENC_Hash []byte //HMAC with Masterkey
}

func CreateUserInside(username string, passwordHash []byte, dsSK userlib.DSSignKey, rsaSK userlib.PKEDecKey) User {
	return User{
		Username: username,
		Password: passwordHash,
		DS_SK:    dsSK,
		RSA_SK:   rsaSK,
	}
}

func CreateEncryptedUser(user User, userKey []byte, userIV []byte, userHMAC []byte) (UserOutside, error) {
	userMarshalled, err := json.Marshal(user)
	if err != nil {
		return UserOutside{}, errors.New("asdfsadfa")
	}

	UserInside_ENC := userlib.SymEnc(userKey, userIV, userMarshalled)

	UserInside_ENC_Hash, err := userlib.HMACEval(userHMAC, UserInside_ENC)
	if err != nil {
		return UserOutside{}, errors.New("asdfsadfa")
	}

	return UserOutside{
		User:      UserInside_ENC,
		User_Hash: UserInside_ENC_Hash,
	}, nil
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	//Check if given username is empty
	if username == "" {
		return nil, errors.New("asdfsadfa")
	}

	passwordHash := userlib.Argon2Key([]byte(password), []byte(username), 16)

	//Get the UUID associated with the username
	usernameas, err := userlib.HashKDF(passwordHash, []byte(username)) //Note this was changed
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}
	User_UUID, err := uuid.FromBytes(usernameas[0:16]) //We slice the first 16 bytes off because that is what uuid.FromBytes wants
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}

	//Checks if there is already a user struct there
	_, ok := userlib.DatastoreGet(User_UUID)
	if ok {
		return nil, errors.New("asdfsadfa")
	}

	DSSignKey, DSVerifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}
	RSA_ENC, RSA_DEC, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}

	err = userlib.KeystoreSet(username+"DS", DSVerifyKey)
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}

	err = userlib.KeystoreSet(username+"RSA", RSA_ENC)
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}

	USER_KEY, err := userlib.HashKDF(passwordHash, []byte("KEY"))
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}
	USER_KEY = USER_KEY[:16]

	USER_HMAC, err := userlib.HashKDF(passwordHash, []byte("HMAC"))
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}
	USER_HMAC = USER_HMAC[:16]

	USER_IV, err := userlib.HashKDF(passwordHash, []byte("IV"))
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}
	USER_IV = USER_IV[:16]

	User_Inside_Return := CreateUserInside(username, passwordHash, DSSignKey, RSA_DEC)

	USER_ENC_UNMARSHALL, err := CreateEncryptedUser(User_Inside_Return, USER_KEY, USER_IV, USER_HMAC)
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}

	USER_ENC, err := json.Marshal(USER_ENC_UNMARSHALL)
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}

	userlib.DatastoreSet(User_UUID, USER_ENC)

	err = Make_File_Library(username, passwordHash)
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}

	return &User_Inside_Return, nil
}

func Make_File_Library(username string, Argon_password []byte) (err error) {
	File_Key, err := userlib.HashKDF(Argon_password, []byte("FileKey")) //Please note this is 64 bytes, need to turn it down to 16 bytes
	if err != nil {
		return errors.New("asdfsadfa")
	}
	File_Key = File_Key[0:16] //That's better

	/* Whatever*/
	File_Key_HMAC, err := userlib.HashKDF(File_Key, []byte("FileKeyHMAC"))
	if err != nil {
		return errors.New("asdfsadfa")
	}

	File_Key_HMAC = File_Key_HMAC[:16]
	/* Whatever*/

	File_Library_UUID_Bytes, err := userlib.HashKDF(Argon_password, []byte("FileLibrary")) //Changed
	if err != nil {
		return errors.New("asdfsadfa")
	}

	File_Library_UUID, err := uuid.FromBytes(File_Library_UUID_Bytes[0:16])
	if err != nil {
		return errors.New("asdfsadfa")
	}

	FileLibrary := FileLibrary{
		File:        make(map[string]uuid.UUID),
		FilesSender: make(map[string]string),
		FilesShared: make(map[string][]uuid.UUID), //uuid.UUID map[string][]uuid.UUID
	}

	FileLibrary_Marshalled, err := json.Marshal(FileLibrary)
	if err != nil {
		return errors.New("asdfsadfa")
	}
	IV := userlib.RandomBytes(16)
	FileLibrary_Marshalled_ENC := userlib.SymEnc(File_Key, IV, FileLibrary_Marshalled)

	FileLibrary_Marshalled_ENC_Hash, err := userlib.HMACEval(File_Key_HMAC, FileLibrary_Marshalled_ENC) //whatever
	if err != nil {
		return errors.New("asdfsadfa")
	}

	FileLibraryOutside := FileLibraryOutside{
		FileLibrary:      FileLibrary_Marshalled_ENC,
		FileLibrary_Hash: FileLibrary_Marshalled_ENC_Hash,
	}

	FileLibraryOutside_Marshalled, err := json.Marshal(FileLibraryOutside)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	userlib.DatastoreSet(File_Library_UUID, FileLibraryOutside_Marshalled)

	return nil
}

func GetUser(username string, password string) (*User, error) {
	passwordHash := userlib.Argon2Key([]byte(password), []byte(username), 16)

	usernameas, err := userlib.HashKDF(passwordHash, []byte(username)) //Changed
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}

	User_UUID, err := uuid.FromBytes(usernameas[0:16]) //This is the UUID where the user SHOULD be stored at
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}

	userDataBytes, ok := userlib.DatastoreGet(User_UUID)
	if !ok {
		return nil, errors.New("asdfsadfa")
	}

	var userOutside_UnMarshalled UserOutside
	err = json.Unmarshal(userDataBytes, &userOutside_UnMarshalled)
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}

	USER_KEY, err := userlib.HashKDF(passwordHash, []byte("KEY"))
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}
	USER_KEY = USER_KEY[:16]

	USER_HMAC, err := userlib.HashKDF(passwordHash, []byte("HMAC"))
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}
	USER_HMAC = USER_HMAC[:16]

	verifyHash, err := userlib.HMACEval(USER_HMAC, userOutside_UnMarshalled.User)
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}

	boo := userlib.HMACEqual(verifyHash, userOutside_UnMarshalled.User_Hash)
	if !boo {
		return nil, errors.New("asdfsadfa")
	}

	userBytes := userlib.SymDec(USER_KEY, userOutside_UnMarshalled.User)

	var userInside User
	err = json.Unmarshal(userBytes, &userInside)
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}

	return &userInside, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	File_Library, err := returnFileLibrary(userdata)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	sender := File_Library.FilesSender[filename]

	if sender == "" {
		return New_File(userdata, filename, content)
	} else {
		return Overwrite(userdata, filename, content)
	}
}

func returnFileLibrary(userdata *User) (FEJLDHF FileLibrary, err error) {
	File_Key, err := userlib.HashKDF(userdata.Password, []byte("FileKey"))
	if err != nil {
		return FileLibrary{}, errors.New("asdfsadfa")
	}
	File_Key = File_Key[:16]

	/* Whatever*/
	File_Key_HMAC, err := userlib.HashKDF(File_Key, []byte("FileKeyHMAC"))
	if err != nil {
		return FileLibrary{}, errors.New("asdfsadfa")
	}

	File_Key_HMAC = File_Key_HMAC[:16]
	/* Whatever*/

	File_Library_UUID_Bytes, err := userlib.HashKDF(userdata.Password, []byte("FileLibrary")) //Please note this was changed from []byte(userdata.Username) to userdata.Password
	if err != nil {
		return FileLibrary{}, errors.New("asdfsadfa")
	}

	UUID_FILE_Library, err := uuid.FromBytes(File_Library_UUID_Bytes[0:16])
	if err != nil {
		return FileLibrary{}, errors.New("asdfsadfa")
	}

	File_Library_Outside_Bytes, ok := userlib.DatastoreGet(UUID_FILE_Library)
	if ok == false {
		return FileLibrary{}, errors.New("asdfsadfa")
	}

	var File_Library_Outside FileLibraryOutside
	err = json.Unmarshal(File_Library_Outside_Bytes, &File_Library_Outside)
	if err != nil {
		return FileLibrary{}, errors.New("asdfsadfa")
	}

	File_Library_New_Hash, err := userlib.HMACEval(File_Key_HMAC, File_Library_Outside.FileLibrary) //Whatever
	if err != nil {
		return FileLibrary{}, errors.New("asdfsadfa")
	}

	bool := userlib.HMACEqual(File_Library_New_Hash, File_Library_Outside.FileLibrary_Hash)
	if bool == false {
		return FileLibrary{}, errors.New("asdfsadfa")
	}

	File_Library_Dec := userlib.SymDec(File_Key, File_Library_Outside.FileLibrary)
	var File_Library FileLibrary
	err = json.Unmarshal(File_Library_Dec, &File_Library)
	if err != nil {
		return FileLibrary{}, errors.New("asdfsadfa")
	}

	return File_Library, nil
}

func Overwrite(userdata *User, filename string, content []byte) error {
	MasterKey, UUID1, _, _, _, _, _ := getImportantInfoForFile(userdata, filename)

	/*Whatever*/
	MasterKey_Hash, err := userlib.HashKDF(MasterKey, []byte("HMAC"))
	if err != nil {
		return errors.New("asdfsadfa")
	}
	MasterKey_Hash = MasterKey_Hash[:16]
	/*Whatever*/

	NumofAppends := 0

	NumofAppends_Masrh, err := json.Marshal(NumofAppends)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	IV := userlib.RandomBytes(16)
	NumofAppends_Masrh_ENC := userlib.SymEnc(MasterKey, IV, NumofAppends_Masrh)
	NumofAppends_Masrh_ENC_Hash, err := userlib.HMACEval(MasterKey_Hash, NumofAppends_Masrh_ENC)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	ResetFileStruct := File{
		NumOfAppendsENC:     NumofAppends_Masrh_ENC,
		NumOfAppendsEncHash: NumofAppends_Masrh_ENC_Hash,
	}

	ResetFileStruct_Marsh, err := json.Marshal(ResetFileStruct)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	userlib.DatastoreSet(UUID1, ResetFileStruct_Marsh)

	userdata.AppendToFile(filename, content)

	return nil
}

func New_File(userdata *User, filename string, content []byte) error {
	UUID1_Bytes := userlib.RandomBytes(16)
	UUID2_Bytes := userlib.RandomBytes(16)
	UUID3_Bytes := userlib.RandomBytes(16)

	UUID1, err := uuid.FromBytes(UUID1_Bytes)
	if err != nil {
		return errors.New("asdfsadfa")
	}
	UUID2, err := uuid.FromBytes(UUID2_Bytes)
	if err != nil {
		return errors.New("asdfsadfa")
	}
	UUID3, err := uuid.FromBytes(UUID3_Bytes)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	MasterKey := userlib.RandomBytes(16)
	UnlockKey := userlib.RandomBytes(16)

	/*Whatever*/
	MasterKey_Hash, err := userlib.HashKDF(MasterKey, []byte("HMAC"))
	if err != nil {
		return errors.New("asdfsadfa")
	}
	MasterKey_Hash = MasterKey_Hash[:16]
	UnlockKey_Hash, err := userlib.HashKDF(UnlockKey, []byte("HMAC"))
	if err != nil {
		return errors.New("asdfsadfa")
	}
	UnlockKey_Hash = UnlockKey_Hash[:16]
	/*Whatever*/

	IV := userlib.RandomBytes(16)

	err = SetUUID1(MasterKey, IV, UUID1, MasterKey_Hash)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	IV = userlib.RandomBytes(16)

	err = SetUUD2(UUID1, userdata, UnlockKey, IV, UUID2, MasterKey, UnlockKey_Hash)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	IV = userlib.RandomBytes(16)

	err = SetUUID3(UUID2, UnlockKey, IV, UUID3, *userdata, UnlockKey_Hash)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	File_Library, err := returnFileLibrary(userdata)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	File_Library.FilesShared[filename] = []uuid.UUID{}                                     //uuid.Nil //GOnna assume this works as intended
	File_Library.FilesShared[filename] = append(File_Library.FilesShared[filename], UUID2) //Just UUID2
	File_Library.File[filename] = UUID3
	File_Library.FilesSender[filename] = userdata.Username
	err = Set_File_Library(*userdata, File_Library)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	err = userdata.AppendToFile(filename, content)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	return nil
}

func SetUUID3(UUID2 uuid.UUID, UnlockKey []byte, IV []byte, UUID3 uuid.UUID, userdata User, UnlockKey_Hash []byte) (err error) {
	RSA_PK, boo := userlib.KeystoreGet(userdata.Username + "RSA")
	if boo == false {
		return errors.New("asdfsadfa")
	}

	UUID2_Marshalled, err := json.Marshal(UUID2)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	Intermediate_encrypted := userlib.SymEnc(UnlockKey, IV, UUID2_Marshalled)

	Intermediate_encrypted_Hash, err := userlib.HMACEval(UnlockKey_Hash, Intermediate_encrypted)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	UnlockKey_encrypted, err := userlib.PKEEnc(RSA_PK, UnlockKey)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	UnlockKey_encrypted_Hash, err := userlib.DSSign(userdata.DS_SK, UnlockKey_encrypted)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	File_Unlock := FileUnlock{
		IntermediateUUID_ENC:      Intermediate_encrypted,
		IntermediateUUID_ENC_Hash: Intermediate_encrypted_Hash,
		UnlockKey_ENC:             UnlockKey_encrypted,
		UnlockKey_ENC_Hash:        UnlockKey_encrypted_Hash,
	}

	FileUnlock_Byte, err := json.Marshal(File_Unlock)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	userlib.DatastoreSet(UUID3, FileUnlock_Byte)
	return nil
}

func SetUUD2(UUID1 uuid.UUID, userdata *User, UnlockKey []byte, IV []byte, UUID2 uuid.UUID, masterkey []byte, UnlockKey_Hash []byte) error {
	Intermediate := Intermediate{
		FileUUID:  UUID1,
		MasterKey: masterkey,
		Recipient: userdata.Username,
	}

	intermediateBytes, err := json.Marshal(Intermediate)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	intermediateBytes_ENC := userlib.SymEnc(UnlockKey, IV, intermediateBytes)
	intermediateBytes_ENC_Hash, err := userlib.HMACEval(UnlockKey_Hash, intermediateBytes_ENC)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	Intermediate_Outside := Intermediate_Outside{
		Intermediate_ENC:      intermediateBytes_ENC,
		Intermediate_ENC_Hash: intermediateBytes_ENC_Hash,
	}

	Intermediate_Outside_Bytes, err := json.Marshal(Intermediate_Outside)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	userlib.DatastoreSet(UUID2, Intermediate_Outside_Bytes)
	return nil
}

func SetUUID1(MasterKey []byte, IV []byte, UUID1 uuid.UUID, MasterKey_Hash []byte) error {
	Num_Of_Appends := 0

	Num_Of_Appends_Bytes, err := json.Marshal(Num_Of_Appends)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	Num_Of_Appends_ENC := userlib.SymEnc(MasterKey, IV, Num_Of_Appends_Bytes)
	Num_Of_Appends_ENC_Hash, err := userlib.HMACEval(MasterKey_Hash, Num_Of_Appends_ENC)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	newFile := File{
		NumOfAppendsENC:     Num_Of_Appends_ENC,
		NumOfAppendsEncHash: Num_Of_Appends_ENC_Hash,
	}

	newFileBytes, err := json.Marshal(newFile)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	userlib.DatastoreSet(UUID1, newFileBytes)
	return nil
}

func Set_File_Library(userdata User, File_Library FileLibrary) (err error) {
	File_Key, err := userlib.HashKDF(userdata.Password, []byte("FileKey"))
	if err != nil {
		return errors.New("asdfsadfa")
	}
	File_Key = File_Key[:16]

	/* Whatever*/
	File_Key_HMAC, err := userlib.HashKDF(File_Key, []byte("FileKeyHMAC"))
	if err != nil {
		return errors.New("asdfsadfa")
	}

	File_Key_HMAC = File_Key_HMAC[:16]
	/* Whatever*/

	File_Library_UUID_Bytes, err := userlib.HashKDF(userdata.Password, []byte("FileLibrary"))
	if err != nil {
		return errors.New("asdfsadfa")
	}

	File_Library_UUID, err := uuid.FromBytes(File_Library_UUID_Bytes[:16])
	if err != nil {
		return errors.New("asdfsadfa")
	}

	File_Library_bytes, err := json.Marshal(File_Library)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	IV := userlib.RandomBytes(16)
	File_Library_bytes_ENC := userlib.SymEnc(File_Key, IV, File_Library_bytes)
	File_Library_bytes_ENC_Hash, err := userlib.HMACEval(File_Key_HMAC, File_Library_bytes_ENC) //whatever
	if err != nil {
		return errors.New("asdfsadfa")
	}

	File_Library_Outside := FileLibraryOutside{
		FileLibrary:      File_Library_bytes_ENC,
		FileLibrary_Hash: File_Library_bytes_ENC_Hash,
	}

	File_Library_Outside_Bytes, err := json.Marshal(File_Library_Outside)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	userlib.DatastoreSet(File_Library_UUID, File_Library_Outside_Bytes)

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	MasterKey, UUID1, NumofAppends, _, _, _, err := getImportantInfoForFile(userdata, filename) //Return values will change later
	if err != nil {
		return errors.New("asdfsadfa")
	}

	/*Whatever*/
	MasterKey_Hash, err := userlib.HashKDF(MasterKey, []byte("HMAC"))
	if err != nil {
		return errors.New("asdfsadfa")
	}
	MasterKey_Hash = MasterKey_Hash[:16]
	/*Whatever*/

	NumofAppends = NumofAppends + 1

	UUID_Append_bytes, err := userlib.HashKDF(MasterKey, []byte(string(NumofAppends)))
	//Look at the warning for this, it says the string cast returns a string of one rune??
	if err != nil {
		return errors.New("asdfsadfa")
	}
	UUID_Append, err := uuid.FromBytes(UUID_Append_bytes[0:16])
	if err != nil {
		return errors.New("asdfsadfa")
	}

	//Marshal Content and encrypt
	IV := userlib.RandomBytes(16)
	content_bytes, err := json.Marshal(content) //Content is already of type []byte, should we marshall? Is it even worth it to change it?
	if err != nil {
		return errors.New("asdfsadfa")
	}

	content_enc := userlib.SymEnc(MasterKey, IV, content_bytes)
	content_enc_hash, err := userlib.HMACEval(MasterKey_Hash, content_enc) //Whatever
	if err != nil {
		return errors.New("asdfsadfa")
	}

	//Store in FileContent
	File_Append := FileContent{
		Content_ENC:      content_enc,
		Content_ENC_Hash: content_enc_hash,
	}

	// Marshal File_Append struct
	File_Append_bytes, err := json.Marshal(File_Append)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	// Store File_Append_bytes in DataStore
	userlib.DatastoreSet(UUID_Append, File_Append_bytes)

	NumofAppends_Bytes, err := json.Marshal(NumofAppends)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	IV = userlib.RandomBytes(16)
	NumofAppends_ENC := userlib.SymEnc(MasterKey, IV, NumofAppends_Bytes)
	NumofAppends_Hash, err := userlib.HMACEval(MasterKey_Hash, NumofAppends_ENC) //Whatever
	if err != nil {
		return errors.New("asdfsadfa")
	}

	newFile := File{
		NumOfAppendsENC:     NumofAppends_ENC,
		NumOfAppendsEncHash: NumofAppends_Hash,
	}

	newFileBytes, err := json.Marshal(newFile)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	userlib.DatastoreSet(UUID1, newFileBytes)

	return nil
}

func getImportantInfoForFile(userdata *User, filename string) (masterKey []byte, File_UUID1 uuid.UUID, NumOfAppend int, unlockKey []byte, IntermediateStruct Intermediate, UUID_OF_INTERMEDIATE uuid.UUID, err error) {
	File_Library, err := returnFileLibrary(userdata)
	if err != nil {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}

	UUID3 := File_Library.File[filename]
	if UUID3 == uuid.Nil {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}

	File_Unlock_Bytes, ok := userlib.DatastoreGet(UUID3)
	if !ok {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}

	var File_Unlock FileUnlock
	err = json.Unmarshal(File_Unlock_Bytes, &File_Unlock)
	if err != nil {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}

	Sender_DS_Verify_Key, boo := userlib.KeystoreGet(File_Library.FilesSender[filename] + "DS")
	if boo == false {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}

	Unlock_Key_Enc := File_Unlock.UnlockKey_ENC
	Unlock_Key_Enc_Hash := File_Unlock.UnlockKey_ENC_Hash

	err = userlib.DSVerify(Sender_DS_Verify_Key, Unlock_Key_Enc, Unlock_Key_Enc_Hash)
	if err != nil {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}

	RSA_SK := userdata.RSA_SK
	Unlock_Key, err := userlib.PKEDec(RSA_SK, Unlock_Key_Enc) //Is this Marshalled??
	if err != nil {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}

	//Unmarshall Unlock_Key??

	/*Whatever*/
	UnlockKey_Hash, err := userlib.HashKDF(Unlock_Key, []byte("HMAC"))
	if err != nil {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}
	UnlockKey_Hash = UnlockKey_Hash[:16]
	/*Whatever*/

	UUID2_Enc := File_Unlock.IntermediateUUID_ENC
	UUID2_Enc_Hash := File_Unlock.IntermediateUUID_ENC_Hash

	UUID2_Enc_Hash2, err := userlib.HMACEval(UnlockKey_Hash, UUID2_Enc)
	if err != nil {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}

	bool := userlib.HMACEqual(UUID2_Enc_Hash, UUID2_Enc_Hash2)
	if !bool {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}

	UUID2_bytes := userlib.SymDec(Unlock_Key, UUID2_Enc)

	var UUID2 uuid.UUID
	err = json.Unmarshal(UUID2_bytes, &UUID2)
	if err != nil {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}

	Intermediate_Outside_Bytes, ok := userlib.DatastoreGet(UUID2)
	if !ok {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}

	var Intermediate_Outside_Struct Intermediate_Outside
	err = json.Unmarshal(Intermediate_Outside_Bytes, &Intermediate_Outside_Struct)
	if err != nil {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}

	Intermediate_Enc := Intermediate_Outside_Struct.Intermediate_ENC
	Intermediate_Enc_Hash := Intermediate_Outside_Struct.Intermediate_ENC_Hash

	Intermediate_Enc_Hash2, err := userlib.HMACEval(UnlockKey_Hash, Intermediate_Enc)
	if err != nil {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}

	bool = userlib.HMACEqual(Intermediate_Enc_Hash, Intermediate_Enc_Hash2)
	if !bool {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}

	Intermediate_Bytes := userlib.SymDec(Unlock_Key, Intermediate_Enc)

	var Intermediate_Struct Intermediate
	err = json.Unmarshal(Intermediate_Bytes, &Intermediate_Struct)
	if err != nil {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}

	MasterKey := Intermediate_Struct.MasterKey
	UUID1 := Intermediate_Struct.FileUUID

	/*Whatever*/
	MasterKey_Hash, err := userlib.HashKDF(MasterKey, []byte("HMAC"))
	if err != nil {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}
	MasterKey_Hash = MasterKey_Hash[:16]
	/*Whatever*/

	File_Struct_Bytes, ok := userlib.DatastoreGet(UUID1)
	if !ok {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}

	var File_Struct File
	err = json.Unmarshal(File_Struct_Bytes, &File_Struct)
	if err != nil {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}

	NumofAppendsEnc := File_Struct.NumOfAppendsENC
	NumofAppendsEnc_Hash := File_Struct.NumOfAppendsEncHash

	NumofAppendsEnc_Hash2, err := userlib.HMACEval(MasterKey_Hash, NumofAppendsEnc)
	if err != nil {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}

	bool = userlib.HMACEqual(NumofAppendsEnc_Hash, NumofAppendsEnc_Hash2)
	if !bool {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}

	NumofAppends_bytes := userlib.SymDec(MasterKey, NumofAppendsEnc)

	var NumofAppends int
	err = json.Unmarshal(NumofAppends_bytes, &NumofAppends)
	if err != nil {
		return nil, uuid.Nil, 0, nil, Intermediate{}, uuid.Nil, errors.New("asdfsadfa")
	}

	//Return everything that is necessary
	return MasterKey, UUID1, NumofAppends, Unlock_Key, Intermediate_Struct, UUID2, nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	MasterKey, _, NumofAppends, _, _, _, err := getImportantInfoForFile(userdata, filename)
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}

	content_to_return, err := collectContent(NumofAppends, MasterKey)
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}

	return content_to_return, nil
}

func collectContent(NumofAppends int, MasterKey []byte) (fullContent []byte, err error) {
	/*Whatever*/
	MasterKey_Hash, err := userlib.HashKDF(MasterKey, []byte("HMAC"))
	if err != nil {
		return nil, errors.New("asdfsadfa")
	}
	MasterKey_Hash = MasterKey_Hash[:16]
	/*Whatever*/

	var content_to_return []byte
	for i := 1; i <= NumofAppends; i++ {
		UUID_bytes, err := userlib.HashKDF(MasterKey, []byte(string(i)))
		if err != nil {
			return nil, errors.New("asdfsadfa")
		}
		UUIDI, err := uuid.FromBytes(UUID_bytes[0:16])
		if err != nil {
			return nil, errors.New("asdfsadfa")
		}

		File_Content_Bytes, ok := userlib.DatastoreGet(UUIDI)
		if !ok {
			return nil, errors.New("asdfsadfa")
		}

		var File_Content FileContent
		err = json.Unmarshal(File_Content_Bytes, &File_Content)
		if err != nil {
			return nil, errors.New("asdfsadfa")
		}

		content_enc := File_Content.Content_ENC
		content_enc_Hash := File_Content.Content_ENC_Hash

		content_enc_Hash2, err := userlib.HMACEval(MasterKey_Hash, content_enc)
		if err != nil {
			return nil, errors.New("asdfsadfa")
		}

		boo := userlib.HMACEqual(content_enc_Hash, content_enc_Hash2)
		if !boo {
			return nil, errors.New("asdfsadfa")
		}

		content_marshaled := userlib.SymDec(MasterKey, content_enc)

		var content []byte
		err = json.Unmarshal(content_marshaled, &content)
		if err != nil {
			return nil, errors.New("asdfsadfa")
		}

		content_to_return = append(content_to_return, content...)

	}
	return content_to_return, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	File_Library, err := returnFileLibrary(userdata)
	if err != nil {
		return uuid.Nil, errors.New("asdfsadfa")
	}

	sender := File_Library.FilesSender[filename]

	_, _, _, Unlock_Key, IntermediateStruct, UUID_OF_Intermediate, err := getImportantInfoForFile(userdata, filename)
	if err != nil {
		return uuid.Nil, errors.New("asdfsadfa")
	}

	if sender == userdata.Username { //If we are the owner of the file, then we need to also deal with an intermediate struct
		IV := userlib.RandomBytes(16)
		return Invite_as_Owner(IntermediateStruct, recipientUsername, IV, File_Library, filename, userdata, Unlock_Key)
	} else if sender == "" {
		return uuid.Nil, errors.New("asdfsadfa") //If we don't get anything back that means we don't have access to this file, so we can't invite anyone to it
	} else {
		IV := userlib.RandomBytes(16)
		return Invite_as_Guest(recipientUsername, UUID_OF_Intermediate, Unlock_Key, IV, userdata)
	}
}

func Invite_as_Guest(recipientUsername string, UUID_OF_Intermediate uuid.UUID, Unlock_Key []byte, IV []byte, userdata *User) (invitationPtr uuid.UUID, err error) {
	return returnAndSetSharedUnlockStruct(recipientUsername, UUID_OF_Intermediate, Unlock_Key, IV, userdata)
}

func returnAndSetSharedUnlockStruct(recipientUsername string, UUID_OF_Intermediate uuid.UUID, Unlock_Key []byte, IV []byte, userdata *User) (invitationPtr uuid.UUID, err error) {
	/*Whatever*/
	UnlockKey_Hash, err := userlib.HashKDF(Unlock_Key, []byte("HMAC"))
	if err != nil {
		return uuid.Nil, errors.New("asdfsadfa")
	}
	UnlockKey_Hash = UnlockKey_Hash[:16]
	/*Whatever*/

	Recipient_RSA_PK, bool := userlib.KeystoreGet(recipientUsername + "RSA")
	if bool == false {
		return uuid.Nil, errors.New("asdfsadfa")
	}

	UUID_OF_Intermediate_Bytes, err := json.Marshal(UUID_OF_Intermediate)
	if err != nil {
		return uuid.Nil, errors.New("asdfsadfa")
	}

	UUID_OF_Intermediate_Bytes_ENC := userlib.SymEnc(Unlock_Key, IV, UUID_OF_Intermediate_Bytes)
	if err != nil {
		return uuid.Nil, errors.New("asdfsadfa")
	}
	UUID_OF_Intermediate_Bytes_ENC_Hash, err := userlib.HMACEval(UnlockKey_Hash, UUID_OF_Intermediate_Bytes_ENC)
	if err != nil {
		return uuid.Nil, errors.New("asdfsadfa")
	}

	Unlock_Key_ENC, err := userlib.PKEEnc(Recipient_RSA_PK, Unlock_Key)
	if err != nil {
		return uuid.Nil, errors.New("asdfsadfa")
	}
	Unlock_Key_ENC_Hash, err := userlib.DSSign(userdata.DS_SK, Unlock_Key_ENC)
	if err != nil {
		return uuid.Nil, errors.New("asdfsadfa")
	}

	FileUnlock_Shared := FileUnlock{
		IntermediateUUID_ENC:      UUID_OF_Intermediate_Bytes_ENC,
		IntermediateUUID_ENC_Hash: UUID_OF_Intermediate_Bytes_ENC_Hash,
		UnlockKey_ENC:             Unlock_Key_ENC,
		UnlockKey_ENC_Hash:        Unlock_Key_ENC_Hash,
	}

	FileUnlock_Shared_Bytes, err := json.Marshal(FileUnlock_Shared)
	if err != nil {
		return uuid.Nil, errors.New("asdfsadfa")
	}

	FileUnlock_Shared_UUID := uuid.New()
	userlib.DatastoreSet(FileUnlock_Shared_UUID, FileUnlock_Shared_Bytes)

	return FileUnlock_Shared_UUID, nil
}

func Invite_as_Owner(IntermediateStruct Intermediate, recipientUsername string, IV []byte, File_Library FileLibrary, filename string, userdata *User, Unlock_Key []byte) (uuid.UUID, error) {
	Shared_Intermediate_Outside_UUID, err := returnAndSetIntermediateStruct(IntermediateStruct, recipientUsername, IV, Unlock_Key)
	if err != nil {
		return uuid.Nil, errors.New("asdfsadfa")
	}

	File_Library.FilesShared[filename] = append(File_Library.FilesShared[filename], Shared_Intermediate_Outside_UUID)

	Set_File_Library(*userdata, File_Library)

	Shared_File_Unlock_UUID, err := returnAndSetSharedUnlockStruct(recipientUsername, Shared_Intermediate_Outside_UUID, Unlock_Key, IV, userdata)
	if err != nil {
		return uuid.Nil, errors.New("asdfsadfa")
	}

	return Shared_File_Unlock_UUID, nil
}

func returnAndSetIntermediateStruct(IntermediateStruct Intermediate, recipientUsername string, IV []byte, UnlockKey []byte) (IntermediateReturnUUID uuid.UUID, err error) {
	/*Whatever*/
	UnlockKey_Hash, err := userlib.HashKDF(UnlockKey, []byte("HMAC"))
	if err != nil {
		return uuid.Nil, errors.New("asdfsadfa")
	}
	UnlockKey_Hash = UnlockKey_Hash[:16]
	/*Whatever*/

	Shared_Intermediate := Intermediate{
		FileUUID:  IntermediateStruct.FileUUID,
		MasterKey: IntermediateStruct.MasterKey,
		Recipient: recipientUsername,
	}

	Shared_Intermediate_Bytes, err := json.Marshal(Shared_Intermediate)
	if err != nil {
		return uuid.Nil, errors.New("asdfsadfa")
	}

	Shared_Intermediate_Bytes_ENC := userlib.SymEnc(UnlockKey, IV, Shared_Intermediate_Bytes)
	Shared_Intermediate_Bytes_ENC_Hash, err := userlib.HMACEval(UnlockKey_Hash, Shared_Intermediate_Bytes_ENC)
	if err != nil {
		return uuid.Nil, errors.New("asdfsadfa")
	}

	IntermediateStruct_For_Shared_User_Outside := Intermediate_Outside{
		Intermediate_ENC:      Shared_Intermediate_Bytes_ENC,
		Intermediate_ENC_Hash: Shared_Intermediate_Bytes_ENC_Hash,
	}

	IntermediateStruct_For_Shared_User_Outside_Bytes, err := json.Marshal(IntermediateStruct_For_Shared_User_Outside)
	if err != nil {
		return uuid.Nil, errors.New("asdfsadfa")
	}

	Shared_Intermediate_Outside_UUID := uuid.New()

	userlib.DatastoreSet(Shared_Intermediate_Outside_UUID, IntermediateStruct_For_Shared_User_Outside_Bytes)
	return Shared_Intermediate_Outside_UUID, nil
}

// TODO: Need to check inside intermediate struct and error if empty
func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	File_Library, err := returnFileLibrary(userdata)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	InvitationStruct, bool := userlib.DatastoreGet(invitationPtr)
	if bool == false {
		return errors.New("asdfsadfa")
	}

	var InvitationStruct_Unmarshalled FileUnlock
	err = json.Unmarshal(InvitationStruct, &InvitationStruct_Unmarshalled)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	if File_Library.File[filename] != uuid.Nil {
		return errors.New("asdfsadfa")
	}

	DS_Verify_Key, boo := userlib.KeystoreGet(senderUsername + "DS")
	if boo == false {
		return errors.New("asdfsadfa")
	}

	err = userlib.DSVerify(DS_Verify_Key, InvitationStruct_Unmarshalled.UnlockKey_ENC, InvitationStruct_Unmarshalled.UnlockKey_ENC_Hash)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	Unlock_Key, err := userlib.PKEDec(userdata.RSA_SK, InvitationStruct_Unmarshalled.UnlockKey_ENC)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	/*Whatever*/
	UnlockKey_Hash, err := userlib.HashKDF(Unlock_Key, []byte("HMAC"))
	if err != nil {
		return errors.New("asdfsadfa")
	}
	UnlockKey_Hash = UnlockKey_Hash[:16]
	/*Whatever*/

	NweIntermediateUUID, err := userlib.HMACEval(UnlockKey_Hash, InvitationStruct_Unmarshalled.IntermediateUUID_ENC)
	if err != nil {
		return errors.New("asdfsadfa")
	}
	bool = userlib.HMACEqual(NweIntermediateUUID, InvitationStruct_Unmarshalled.IntermediateUUID_ENC_Hash)
	if bool == false {
		return errors.New("asdfsadfa")
	}

	NweIntermediateUUID_Decrypt := userlib.SymDec(Unlock_Key, InvitationStruct_Unmarshalled.IntermediateUUID_ENC)

	var NweIntermediateUUID_Decrypt_Unmarsh uuid.UUID //error on unmarshalling
	err = json.Unmarshal(NweIntermediateUUID_Decrypt, &NweIntermediateUUID_Decrypt_Unmarsh)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	_, boo = userlib.DatastoreGet(NweIntermediateUUID_Decrypt_Unmarsh)
	if boo == false {
		return errors.New("asdfsadfa")
	}

	File_Library.File[filename] = invitationPtr
	File_Library.FilesSender[filename] = senderUsername

	err = Set_File_Library(*userdata, File_Library)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// Fetch the File_Library using the username
	File_Library, err := returnFileLibrary(userdata)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	// Find the UUID associated with the filename in File_Library
	fileUUID_Sender := File_Library.FilesSender[filename]
	if fileUUID_Sender == "" {
		return errors.New("asdfsadfa")
	}

	_, _, Num_Of_Append, UnlockKey, IntermediateStruct, UUID_OF_Intermediate, err := getImportantInfoForFile(userdata, filename)
	if err != nil {
		return errors.New("asdfsadfa")
	}
	UUID_OF_Intermediate = UUID_OF_Intermediate //keep the compiler happy

	// Generate a new Master Key
	New_MasterKey := userlib.RandomBytes(16) //This is what every single intermediate struct will be updated with
	IV := userlib.RandomBytes(16)
	// Generate a new UUID for the updated FileStruct
	NEW_File_UUID_ENC := uuid.New() //This is what every single intermediate struct will be updated with

	/*Whatever*/
	New_MasterKey_Hash, err := userlib.HashKDF(New_MasterKey, []byte("HMAC"))
	if err != nil {
		return errors.New("asdfsadfa")
	}
	New_MasterKey_Hash = New_MasterKey_Hash[:16]
	UnlockKey_Hash, err := userlib.HashKDF(UnlockKey, []byte("HMAC"))
	if err != nil {
		return errors.New("asdfsadfa")
	}
	UnlockKey_Hash = UnlockKey_Hash[:16]
	/*Whatever*/

	//Marshal Num_Of_Append
	Num_Of_Append_bytes, err := json.Marshal(Num_Of_Append)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	Num_Of_Append_Updated_Encrypt := userlib.SymEnc(New_MasterKey, IV, Num_Of_Append_bytes)
	Num_Of_Append_Updated_Encrypt_Hash, err := userlib.HMACEval(New_MasterKey_Hash, Num_Of_Append_Updated_Encrypt)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	File_New := File{
		NumOfAppendsENC:     Num_Of_Append_Updated_Encrypt,
		NumOfAppendsEncHash: Num_Of_Append_Updated_Encrypt_Hash,
	}

	File_New_Marshalled, err := json.Marshal(File_New)
	if err != nil {
		return errors.New("asdfsadfa")
	}

	userlib.DatastoreSet(NEW_File_UUID_ENC, File_New_Marshalled)

	//Generate the new locations of the file and store them
	for i := 1; i <= Num_Of_Append; i++ {
		//Generate the new FileContent UUID
		UUID_Bytes, err := userlib.HashKDF(New_MasterKey, []byte(string(i)))
		if err != nil {
			return errors.New("asdfsadfa")
		}

		UUID_OF_New_FileContent, err := uuid.FromBytes(UUID_Bytes[0:16])
		if err != nil {
			return errors.New("asdfsadfa")
		}

		UUID_OF_Old_Content_Bytes, err := userlib.HashKDF(IntermediateStruct.MasterKey, []byte(string(i)))
		if err != nil {
			return errors.New("asdfsadfa")
		}

		UUID_OF_Old_Content, err := uuid.FromBytes(UUID_OF_Old_Content_Bytes[0:16])
		if err != nil {
			return errors.New("asdfsadfa")
		}

		//Collect Old Content
		Old_FileContent_Marshalled, bool := userlib.DatastoreGet(UUID_OF_Old_Content)
		if bool == false {
			return errors.New("asdfsadfa")
		}

		var Old_FileContent FileContent
		err = json.Unmarshal(Old_FileContent_Marshalled, &Old_FileContent)
		if err != nil {
			return errors.New("asdfsadfa")
		}

		MasterKey := IntermediateStruct.MasterKey
		/*Whatever*/
		MasterKey_Hash, err := userlib.HashKDF(MasterKey, []byte("HMAC"))
		if err != nil {
			return errors.New("asdfsadfa")
		}
		MasterKey_Hash = MasterKey_Hash[:16]
		/*Whatever*/

		//Calcualte the hash
		New_Content_ENC_Hash, err := userlib.HMACEval(MasterKey_Hash, Old_FileContent.Content_ENC)
		if err != nil {
			return errors.New("asdfsadfa")
		}

		//Compare teh hash
		bool = userlib.HMACEqual(New_Content_ENC_Hash, Old_FileContent.Content_ENC_Hash)
		if bool == false {
			return errors.New("asdfsadfa")
		}

		IV := userlib.RandomBytes(16)
		Old_Content_Dec := userlib.SymDec(IntermediateStruct.MasterKey, Old_FileContent.Content_ENC)
		Old_Content_Updated_Enc := userlib.SymEnc(New_MasterKey, IV, Old_Content_Dec)

		Old_Content_Updated_Enc_Hash, err := userlib.HMACEval(New_MasterKey_Hash, Old_Content_Updated_Enc)
		if err != nil {
			return errors.New("asdfsadfa")
		}

		//If safe, copy the files over
		New_FileContent := FileContent{
			Content_ENC:      Old_Content_Updated_Enc,
			Content_ENC_Hash: Old_Content_Updated_Enc_Hash,
		}

		//Marshal New_FileContent
		New_FileContent_bytes, err := json.Marshal(New_FileContent)
		if err != nil {
			return errors.New("asdfsadfa")
		}

		//Store into new UUID
		userlib.DatastoreSet(UUID_OF_New_FileContent, New_FileContent_bytes)
		userlib.DatastoreDelete(UUID_OF_Old_Content)
	}

	array_of_interest := File_Library.FilesShared[filename]

	recipeintFound := 0
	for j := 0; j < len(array_of_interest); j++ {
		UUID_OF_Curr_Intermediate := array_of_interest[j]

		Curr_Intermediate_Outside_Marshalled, ok := userlib.DatastoreGet(UUID_OF_Curr_Intermediate) //Encrypted with UnlockKey //Note FIx this by unmarshalling it
		if !ok {
			return errors.New("asdfsadfa")
		}

		var Curr_Intermediate_Outside Intermediate_Outside
		err = json.Unmarshal(Curr_Intermediate_Outside_Marshalled, &Curr_Intermediate_Outside)
		if err != nil {
			return errors.New("asdfsadfa")
		}

		New_Intermediate_ENC_Hash, err := userlib.HMACEval(UnlockKey_Hash, Curr_Intermediate_Outside.Intermediate_ENC)
		if err != nil {
			return errors.New("asdfsadfa")
		}
		bool := userlib.HMACEqual(New_Intermediate_ENC_Hash, Curr_Intermediate_Outside.Intermediate_ENC_Hash)
		if bool == false {
			return errors.New("asdfsadfa")
		}

		Curr_Intermediate := userlib.SymDec(UnlockKey, Curr_Intermediate_Outside.Intermediate_ENC)

		var Curr_Intermediate_UnMarsh Intermediate
		err = json.Unmarshal(Curr_Intermediate, &Curr_Intermediate_UnMarsh)
		if err != nil {
			return errors.New("asdfsadfa")
		}

		if Curr_Intermediate_UnMarsh.Recipient == recipientUsername {
			recipeintFound = 1
		}
	}

	if recipeintFound == 0 {
		return errors.New("asdfsadfa")
	}

	for j := 0; j < len(array_of_interest); j++ {
		UUID_OF_Curr_Intermediate := array_of_interest[j]

		Curr_Intermediate_Outside_Marshalled, ok := userlib.DatastoreGet(UUID_OF_Curr_Intermediate) //Encrypted with UnlockKey
		if !ok {
			return errors.New("asdfsadfa")
		}

		var Curr_Intermediate_Outside Intermediate_Outside
		err = json.Unmarshal(Curr_Intermediate_Outside_Marshalled, &Curr_Intermediate_Outside)
		if err != nil {
			return errors.New("asdfsadfa")
		}

		New_Intermediate_ENC_Hash, err := userlib.HMACEval(UnlockKey_Hash, Curr_Intermediate_Outside.Intermediate_ENC)
		if err != nil {
			return errors.New("asdfsadfa")
		}
		bool := userlib.HMACEqual(New_Intermediate_ENC_Hash, Curr_Intermediate_Outside.Intermediate_ENC_Hash)
		if bool == false {
			return errors.New("asdfsadfa")
		}

		Curr_Intermediate := userlib.SymDec(UnlockKey, Curr_Intermediate_Outside.Intermediate_ENC)

		var Curr_Intermediate_UnMarsh Intermediate
		err = json.Unmarshal(Curr_Intermediate, &Curr_Intermediate_UnMarsh)
		if err != nil {
			return errors.New("asdfsadfa")
		}

		if Curr_Intermediate_UnMarsh.Recipient == recipientUsername {
			userlib.DatastoreDelete(UUID_OF_Curr_Intermediate)
			continue
		}

		Curr_Intermediate_UnMarsh.FileUUID = NEW_File_UUID_ENC
		Curr_Intermediate_UnMarsh.MasterKey = New_MasterKey

		//Need to also set this back into datastore to update it

		Updated_Curr_Intermediate_Marsh, err := json.Marshal(Curr_Intermediate_UnMarsh)
		if err != nil {
			return errors.New("asdfsadfa")
		}

		IV := userlib.RandomBytes(16)
		Updated_Curr_Intermediate_Marsh_ENC := userlib.SymEnc(UnlockKey, IV, Updated_Curr_Intermediate_Marsh)
		Updated_Curr_Intermediate_Marsh_ENC_Hash, err := userlib.HMACEval(UnlockKey_Hash, Updated_Curr_Intermediate_Marsh_ENC)
		if err != nil {
			return errors.New("asdfsadfa")
		}

		Updated_Intermediate := Intermediate_Outside{
			Intermediate_ENC:      Updated_Curr_Intermediate_Marsh_ENC,
			Intermediate_ENC_Hash: Updated_Curr_Intermediate_Marsh_ENC_Hash,
		}

		Updated_Intermediate_Marsh, err := json.Marshal(Updated_Intermediate)
		if err != nil {
			return errors.New("asdfsadfa")
		}

		userlib.DatastoreSet(UUID_OF_Curr_Intermediate, Updated_Intermediate_Marsh)
	}
	return nil

}
