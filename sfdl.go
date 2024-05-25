package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"os"
)

var Server_Name string
var Server_Uppa string
var Server_Host string
var Server_Port int
var Server_User string = "anonymouse"
var Server_Pass string = "anonymouse@sfdlsauger.go"
var Server_Path []string

type SFDLFile struct {
	XMLName        xml.Name         `xml:"SFDLFile"`
	Description    string           `xml:"Description"`
	Uploader       string           `xml:"Uploader"`
	Encrypted      bool             `xml:"Encrypted"`
	ConnectionInfo ConnectionInfo   `xml:"ConnectionInfo"`
	BulkFolderPath []BulkFolderPath `xml:"Packages>SFDLPackage>BulkFolderList>BulkFolder"`
}

type ConnectionInfo struct {
	XMLName  xml.Name `xml:"ConnectionInfo"`
	Host     string   `xml:"Host"`
	Port     int      `xml:"Port"`
	Username string   `xml:"Username"`
	Password string   `xml:"Password"`
}

type BulkFolderPath struct {
	XMLName        xml.Name `xml:"BulkFolder"`
	BulkFolderPath string   `xml:"BulkFolderPath"`
}

func OpenSFDL(filepath, password string) error {
	file, err := os.Open(filepath)
	if err != nil {
		fmt.Println("Error: Unable to open SFDL file!")
		panic(err)
	}
	defer file.Close()

	var sfdlFile SFDLFile
	decoder := xml.NewDecoder(file)
	if err := decoder.Decode(&sfdlFile); err != nil {
		fmt.Println("Error: Unable to get XML data from SFDL file!")
		panic(err)
	}

	if DEBUG {
		fmt.Printf("Encrypted: %t\n", sfdlFile.Encrypted)
		fmt.Printf("Description: %s\n", sfdlFile.Description)
		fmt.Printf("Uploader: %s\n", sfdlFile.Uploader)
		fmt.Printf("Host: %s\nPort: %d\nUsername: %s\nPassword: %s\n",
			sfdlFile.ConnectionInfo.Host,
			sfdlFile.ConnectionInfo.Port,
			sfdlFile.ConnectionInfo.Username,
			sfdlFile.ConnectionInfo.Password)
	}

	for _, path := range sfdlFile.BulkFolderPath {
		if DEBUG {
			fmt.Printf("Path: %s\n", path.BulkFolderPath)
		}
		Server_Path = append(Server_Path, path.BulkFolderPath)
	}

	Server_Name = sfdlFile.Description
	Server_Uppa = sfdlFile.Uploader
	Server_Host = sfdlFile.ConnectionInfo.Host
	Server_Port = sfdlFile.ConnectionInfo.Port
	Server_User = sfdlFile.ConnectionInfo.Username
	Server_Pass = sfdlFile.ConnectionInfo.Password

	if sfdlFile.Encrypted {
		Server_Name = decryptString(password, Server_Name)
		Server_Uppa = decryptString(password, Server_Uppa)
		Server_Host = decryptString(password, Server_Host)
		Server_User = decryptString(password, Server_User)
		Server_Pass = decryptString(password, Server_Pass)

		for i, path := range Server_Path {
			Server_Path[i] = decryptString(password, path)
		}
	}

	if DEBUG {
		fmt.Println("Name: " + Server_Name)
		fmt.Println("Uppa: " + Server_Uppa)
		fmt.Println("Host: " + Server_Host)
		fmt.Println("Port: ", Server_Port)
		fmt.Println("User: " + Server_User)
		fmt.Println("Pass: " + Server_Pass)
		fmt.Println("Path: ", Server_Path)
	}

	return nil
}

func decryptString(password string, text string) string {
	decryptedText, err := aes128cbc(password, text)
	if err != nil {
		fmt.Println("Error: AES_128_CBC unable to decrypt string!")
		panic(err)
	}
	return string(decryptedText)
}

func aes128cbc(password, encryptedText string) (string, error) {
	hasher := md5.New()
	hasher.Write([]byte(password))
	key, _ := hex.DecodeString(hex.EncodeToString(hasher.Sum(nil)))

	decodedText, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(decodedText) < aes.BlockSize {
		panic("Error: AES_128_CBC decodedText too short")
	}

	iv := decodedText[:aes.BlockSize]
	decodedText = decodedText[aes.BlockSize:]

	if len(decodedText)%aes.BlockSize != 0 {
		panic("Error: AES_128_CBC decodedText is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decodedText, decodedText)

	return string(pkcs5Unpad(decodedText)), nil
}

func pkcs5Unpad(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	padding := int(data[len(data)-1])
	if padding >= len(data) {
		return nil
	}
	return data[:len(data)-padding]
}
