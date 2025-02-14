package proj2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"
	_ "github.com/google/uuid"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}
//TEST USER RETRIEVAL
func TestGet(t *testing.T) {
	clear()
	t.Log("Get user test")
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	result, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to retrieve user", err)
	}
	_ = u
	_ = result
}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestAppend(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	//userlib.DatastoreResetBandwidth()
	v := []byte("This is a test")
	u.StoreFile("file1", v)
	//t.Log("VIBE")
	//t.Log(userlib.DatastoreGetBandwidth())
	//userlib.DatastoreResetBandwidth()
	
	u.AppendFile("file1", []byte(" with the append!"))
	//t.Log("CHECK")
	//t.Log(userlib.DatastoreGetBandwidth())
	v3 := []byte("This is a test with the append!")
	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v2, v3) {
		t.Error("Downloaded file is not the same", v2, v3)
		return
	}
}


func TestPUBLICShare(t *testing.T) {
	clear()
	file1data := "File 1 data woohoo"
	otherAppend := " Other append to file"
	finalStr := []byte("File 1 data woohoo Other append to file")
	u, err := InitUser("nick", "weaver")
	u2, err := InitUser("paul", "legler")

	u.StoreFile("file1", []byte(file1data))
	token, err := u.ShareFile("file1", "paul")
	u2.ReceiveFile("file2", "nick", token)
	_ = err

	u2.AppendFile("file2", []byte(otherAppend))
	ogLoad, err := u.LoadFile("file1")
	if !reflect.DeepEqual(ogLoad, finalStr) {
		t.Error("original owner does not see update:", string(ogLoad), string(finalStr))
	}

}
func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var accessToken uuid.UUID

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
}
