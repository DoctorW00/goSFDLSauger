package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var VERSION string = "1.0.1"
var DEBUG bool = false
var SFDLPassword string = "mlcboard.com"
var DestinationDownloadPath string
var MaxConcurrentDownloads int = 3
var Download_Size uint64
var SFDL_Files []string

func main() {
	clearConsole()
	fmt.Println("goSFDLSauger v" + VERSION + " (GrafSauger)")
	printLogo()

	input_sfdl := flag.String("i", "", "SFDL File")
	download_path := flag.String("d", "", "Download Path")
	sfdl_password := flag.String("p", "", "SFDL Password")
	max_threds := flag.Int("t", 3, "Max. Download Threads")

	flag.Parse()

	errors := 0
	sfdl_file := ""

	if *input_sfdl == "" {
		cPath, err := GetCurrentPath()
		if err != nil {
			fmt.Println("Error: Local path error: ", err)
			errors++
		} else {
			FillSFDLFilesArray(cPath)
			if len(SFDL_Files) > 0 {
				sfdl_file = SFDL_Files[0]
				fmt.Println("SFDL: " + sfdl_file)
			} else {
				fmt.Println("Error: No SFDL files found in: " + cPath)
				errors++
			}
		}
	} else {
		sfdl_file = *input_sfdl
		fmt.Println("SFDL: " + sfdl_file)
	}

	if *download_path == "" {
		currentPath, err := os.Getwd()
		if err != nil {
			fmt.Println("Error finding local path:", err)
			errors++
		} else {
			DestinationDownloadPath = currentPath
		}
	} else {
		DestinationDownloadPath = *download_path
	}

	if *sfdl_password != "" {
		SFDLPassword = *sfdl_password
	}

	if *max_threds > 0 {
		MaxConcurrentDownloads = *max_threds
	}

	if errors > 0 {
		flag.Usage()
		os.Exit(errors)
	}

	StartTango(sfdl_file)

}

func printLogo() {
	asciiLogo := `
             _________________ _      _____                             
            /  ___|  ___|  _  \ |    /  ___|                            
  __ _  ___ \ ` + "`" + `--.| |_  | | | | |    \ ` + "`" + `--.  __ _ _   _  __ _  ___ _ __ 
 / _` + "`" + ` |/ _ \ ` + "`" + `--. \  _| | | | | |     ` + "`" + `--. \/ _` + "`" + ` | | | |/ _` + "`" + ` |/ _ \ '__|
| (_| | (_) /\__/ / |   | |/ /| |____/\__/ / (_| | |_| | (_| |  __/ |   
 \__, |\___/\____/\_|   |___/ \_____/\____/ \__,_|\__,_|\__, |\___|_|   
  __/ |                                                  __/ |          
 |___/                                                  |___/           
`
	fmt.Println(asciiLogo)
}

func StartTango(sfdl_file string) {
	err := OpenSFDL(sfdl_file, SFDLPassword)
	if err != nil {
		fmt.Println("Error: Unable to read/decrypt SFDL file!")
		return
	}

	fmt.Println("FTP Index for: " + Server_Name)

	for _, path := range Server_Path {
		err := GetFTPIndex(path)
		if err != nil {
			fmt.Println("Error: FTP Index-Error!")
			return
		}
	}

	if len(Server_File) < MaxConcurrentDownloads {
		MaxConcurrentDownloads = len(Server_File)
	}

	fmt.Printf("Loading %d files (%s) using %d threads!\n", len(Server_File), FormatBytes(Download_Size), MaxConcurrentDownloads)

	err2 := StartFTPDownloads()
	if err2 != nil {
		fmt.Println("Error: FTP Download error!")
		return
	}

	time.Sleep(2 * time.Second)

	fmt.Println("Moving SFDL file to download path ...")
	dirPath := filepath.Dir(sfdl_file)
	sfdl_from := sfdl_file
	sfdl_to := RemoveDuplicateSlashes(DestinationDownloadPath + "/" + Server_Name + "/" + filepath.Base(sfdl_file))
	err3 := os.Rename(sfdl_from, sfdl_to)
	if err3 != nil {
		fmt.Println("Error moving SFDL file! ", err)
		return
	}

	time.Sleep(2 * time.Second)

	FillSFDLFilesArray(dirPath)

	time.Sleep(2 * time.Second)

	if len(SFDL_Files) > 0 {
		next_sfdl_file := SFDL_Files[0]
		if next_sfdl_file != "" {
			clearConsole()
			fmt.Println("goSFDLSauger v" + VERSION + " (GrafSauger)")
			printLogo()
			fmt.Println("SFDL: " + next_sfdl_file)
			StartTango(next_sfdl_file)
		}
	} else {
		fmt.Println("All loaded, all done, bye!")
	}
}

func clearConsole() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else {
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

func FormatBytes(bytes uint64) string {
	sizes := []string{"B", "KB", "MB", "GB", "TB"}

	var sizeIndex int
	var sizeFloat float64 = float64(bytes)

	for sizeIndex < len(sizes)-1 && sizeFloat >= 1000 {
		sizeIndex++
		sizeFloat /= 1000
	}
	return fmt.Sprintf("%.2f %s", sizeFloat, sizes[sizeIndex])
}

func GetCurrentPath() (string, error) {
	currentPath, err := os.Getwd()
	if err != nil {
		fmt.Println("Error finding local path:", err)
		return "", err
	}
	return currentPath, nil
}

func FillSFDLFilesArray(sfdl_files_path string) {
	SFDL_Files = SFDL_Files[:0]
	entries, err := os.ReadDir(sfdl_files_path)
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sfdl") {
			SFDL_Files = append(SFDL_Files, entry.Name())
		}
	}
}
