package proj2

// CS 161 Project 2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	"github.com/cs161-staff/userlib"

	// The JSON library will be useful for serializing go structs.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/json.html.
	"encoding/json"

	// Likewise, useful for debugging, etc.
	"encoding/hex"

	// The Datastore requires UUIDs to store key-value entries.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/uuid.html.
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	"strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// User is the structure definition for a user record.
type User struct {
	Username string
	Salt []byte
	PKey userlib.PKEDecKey
	AppendMap map[string]int
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// Assign all struct properties
	userdata.Username = username
	userdata.Salt = userlib.RandomBytes(20)
	pubKey, privKey, err := userlib.PKEKeyGen()
	userdata.PKey = privKey
	userdata.AppendMap = make(map[string]int)
	// Send public key to Keystore
	_= pubKey
	userlib.KeystoreSet(username, pubKey)

	// Create UUID to store in Datastore
	resUUID := bytesToUUID(userlib.Hash([]byte(username + password))[:16])
	//userlib.DebugMsg("TEST: %v", resUUID.String())
	bytes, _ := json.Marshal(userdata)
	//ENCRYPT USER DATA BEFORE SENDING TO STORE
	userlib.DatastoreSet(resUUID, bytes)
	return &userdata, nil
}

// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	resUUID := bytesToUUID(userlib.Hash([]byte(username + password))[:16])
	getRes, _ := userlib.DatastoreGet(resUUID)
	if getRes == nil {
		err = errors.New("Username or password incorrect!")
	}
	json.Unmarshal(getRes, &userdata)
	userdataptr = &userdata
	return userdataptr, err
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

	//TODO: This is a toy implementation.
	storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	jsonData, _ := json.Marshal(data)
	userlib.DatastoreSet(storageKey, jsonData)
	//End of toy implementation

	return
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	//dataBytes, err := userdata.LoadFile(filename)
	m := userdata.AppendMap
	result := m[filename]
	if (result == 0) {
		m[filename] = 1
	} else {
		m[filename] = m[filename] + 1
	}
	userlib.DebugMsg(strconv.Itoa(m[filename]))
	userlib.DebugMsg("DB CHECK")
	//userlib.DebugMsg(string(dataBytes))
	//for i := 0; i < len(data); i++ {
	//	dataBytes = append(dataBytes, data[i])
	//}
	newFilename := filename + "_" + strconv.Itoa(m[filename])
	//userlib.DebugMsg(newFilename)
	userdata.StoreFile(newFilename, data)
	return
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {
	storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	appendNum := userdata.AppendMap[filename]
	
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}
	json.Unmarshal(dataJSON, &dataBytes)
	if (appendNum != 0) {
		//userlib.DebugMsg("append case")
		for i := 0; i < appendNum; i++ {
			storageKey, _ := uuid.FromBytes([]byte(filename + "_" + strconv.Itoa(i + 1) + userdata.Username)[:16])
			dataJSON, ok := userlib.DatastoreGet(storageKey)
			_ = ok
			var newDataBytes []byte
			json.Unmarshal(dataJSON, &newDataBytes)
			//userlib.DebugMsg("APPEND CHECK")
			//userlib.DebugMsg(string(newDataBytes))
			dataBytes = append(dataBytes, newDataBytes...)
		}
	}
	// TODO: CHECK MAC OF FILE TO FIGHT TAMPERING

	// IF FILE IS SHARED, CHANGE POINTER TO SHARED FILE
	if (len(dataBytes) > 5 && (string(dataBytes)[:5]) == "share") {
		storageKey, _ = uuid.ParseBytes(dataBytes[5:])
		dataJSON, ok := userlib.DatastoreGet(storageKey)
		json.Unmarshal(dataJSON, &dataBytes)
		_ = dataJSON
		_ = ok
	}
	return dataBytes, nil
}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {
	
	// Retrieve UUID of requested file
	accessToken, _ = uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	return accessToken, nil
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {
	/*var dataBytes []byte
	dataJSON, ok := userlib.DatastoreGet(accessToken)
	if !ok {
		return errors.New(strings.ToTitle("File not found!"))
	}
	json.Unmarshal(dataJSON, &dataBytes)
	*/
	//userlib.DebugMsg(accessToken.String())
	storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	//userlib.DebugMsg("RECEIVED")
	//userlib.DebugMsg(storageKey.String())
	//testArr := []byte(accessToken)
	//d, _ := json.Marshal(accessToken)
	//uid := uuid.New()
	uid := []byte("share" + accessToken.String())
	d, _ := json.Marshal(uid)
	
	var result uuid.UUID
	err := json.Unmarshal(d, &result)
	//userlib.DebugMsg("CHECK")
	//userlib.DebugMsg(result.String())
	_ = err
	
	
	//jsonData, _ := json.Marshal(testArr)
	userlib.DatastoreSet(storageKey, d)

	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	return
}
