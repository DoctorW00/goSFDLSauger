package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var VERSION string = "1.2.4"
var DEBUG bool = false
var SFDLPassword string = "mlcboard.com"
var DestinationDownloadPath string
var MaxConcurrentDownloads int = 3
var Download_Size uint64
var SFDL_Files []string
var UseUNRARUnZIP bool = true
var UseWebserver bool = false
var UseWebserverHost = "0.0.0.0"
var UseWebserverPort = 8080
var LoaderLogs []string
var DownloadLogs []string
var UseMQTT = false
var mqtt_Broker = ""
var mqtt_Topic = "goSFDLSauger"
var mqtt_User = ""
var mqtt_Pass = ""
var UseFTPProxy = false
var ftpProxy_IP = ""
var ftpProxy_Port int16
var ftpProxy_User = ""
var ftpProxy_Pass = ""
var ftp_Timeouts = 30 * time.Second

var wgLoader sync.WaitGroup
var isDownloadRunning bool = false // true if the download cycle is running

func main() {
	clearConsole()
	versionLine := "goSFDLSauger v" + VERSION + " (GrafSauger)"
	fmt.Println(versionLine)
	AddLoaderLog(versionLine)
	printLogo()

	input_sfdl := flag.String("i", "", "SFDL File")
	download_path := flag.String("d", "", "Download Path")
	sfdl_password := flag.String("p", "", "SFDL Password")
	max_threds := flag.Int("t", 3, "Max. Download Threads")
	useUnRARUnZip := flag.Bool("u", true, "Use UnRAR / UnZIP")

	// WebGUI
	useWebserver := flag.Bool("www", false, "Webserver GUI (false)")
	webserverHost := flag.String("www_host", "0.0.0.0", "Webserver IP/Host (0.0.0.0)")
	webserverPort := flag.Int("www_port", 8080, "Webserver Port (8080)")

	// MQTT
	mqttBroker := flag.String("mqtt_Broker", "", "MQTT Broker (tcp://127.0.0.1:1883)")
	mqttTopic := flag.String("mqtt_Topic", "", "MQTT Topic")
	mqttUser := flag.String("mqtt_User", "", "MQTT Username")
	mqttPass := flag.String("mqtt_Pass", "", "MQTT Password/Token")

	// FTP proxy
	ftpProxyIP := flag.String("ftpProxy_IP", "", "IP/DNS FTP Proxy (SOCKS5)")
	ftpProxyPort := flag.Int("ftpProxy_Port", 0, "FTP Proxy Port")
	ftpProxyUser := flag.String("ftpProxy_User", "", "FTP Proxy Username")
	ftpProxyPass := flag.String("ftpProxy_Pass", "", "FTP Proxy Password")

	// ftp timeouts
	ftpTimeouts := flag.Duration("ftpTimeouts", 30*time.Second, "FTP timeout in seconds")

	flag.Parse()

	errors := 0
	sfdl_file := ""

	if *ftpTimeouts != 0 {
		ftp_Timeouts = *ftpTimeouts
	}

	if *ftpProxyIP != "" && *ftpProxyPort != 0 {
		UseFTPProxy = true
		ftpProxy_IP = *ftpProxyIP
		ftpProxy_Port = int16(*ftpProxyPort)

		if *ftpProxyUser != "" && *ftpProxyPass != "" {
			ftpProxy_User = *ftpProxyUser
			ftpProxy_Pass = *ftpProxyPass
		}
	}

	if *mqttBroker != "" {
		UseMQTT = true
		mqtt_Broker = *mqttBroker

		if *mqttTopic != "" {
			mqtt_Topic = *mqttTopic
		}

		if *mqttUser != "" {
			mqtt_User = *mqttUser

			if *mqttPass != "" {
				mqtt_Pass = *mqttPass
			}
		}

		go func() {
			err := startMQTTClient()
			if err != nil {
				fmt.Println(err)
			}
		}()

		time.Sleep(2 * time.Second)
	}

	if *useWebserver {
		UseWebserver = true
		if *webserverHost != "0.0.0.0" {
			UseWebserverHost = *webserverHost
		}
		if *webserverPort != 8080 {
			UseWebserverPort = *webserverPort
		}
		wgLoader.Add(1)
		go GoWebserver(UseWebserverPort, UseWebserverHost)
	} else {
		UseWebserver = false
	}

	if UseWebserver {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			fmt.Println("error getting users default-home directory:", err)
		}

		DestinationDownloadPath = filepath.Join(homeDir + "/Downloads")
		_, err = os.Stat(DestinationDownloadPath)
		if os.IsNotExist(err) {
			DestinationDownloadPath = ""
			fmt.Println("error users default download directory does not exist:", err)
		}
	}

	if *input_sfdl == "" {
		useDestPath := ""
		if UseWebserver {
			useDestPath = filepath.Join(DestinationDownloadPath + "/sfdl_files")
			_, err := os.Stat(useDestPath)
			if err == nil {
				FillSFDLFilesArray(useDestPath, "")
			}
		} else {
			cPath, err := GetCurrentPath()
			if err != nil {
				fmt.Println("error: local path error: ", err)
				errors++
			} else {
				useDestPath = cPath
			}
		}

		_, err := os.Stat(useDestPath)
		if err == nil {
			FillSFDLFilesArray(useDestPath, "")
		}

		if len(SFDL_Files) > 0 {
			sfdl_file = SFDL_Files[0]
			fmt.Println("SFDL: " + sfdl_file)
			AddLoaderLog("SFDL: " + sfdl_file)
		} else {
			fmt.Println("error: no SFDL files found in: " + useDestPath)
			AddLoaderLog("error: no SFDL files found in: " + useDestPath)
			errors++
		}
	} else {
		sfdl_file = *input_sfdl
		fmt.Println("SFDL: " + sfdl_file)
		AddLoaderLog("SFDL: " + sfdl_file)
	}

	if *download_path == "" && DestinationDownloadPath == "" {
		currentPath, err := os.Getwd()
		if err != nil {
			fmt.Println("error finding local path:", err)
			errors++
		} else {
			DestinationDownloadPath = currentPath
		}
	} else {
		if DestinationDownloadPath == "" {
			DestinationDownloadPath = *download_path
		}
	}

	if *sfdl_password != "" {
		SFDLPassword = *sfdl_password
	}

	if *max_threds > 0 {
		MaxConcurrentDownloads = *max_threds
	}

	if *useUnRARUnZip {
		UseUNRARUnZIP = true
	} else {
		UseUNRARUnZIP = false
	}

	if errors > 0 {
		if UseWebserver {
			wgLoader.Wait()
		} else {
			fmt.Println("Too many errors:", errors)
			flag.Usage()
			os.Exit(errors)
		}
	} else {
		startLoaderFunctions(sfdl_file)
	}
}

func startLoaderFunctions(sfdl_file string) {
	if isDownloadRunning {
		fmt.Println("error: loader is already running!")
		AddLoaderLog("error: loader is already running!")
	} else {
		isDownloadRunning = true
		// wgLoader.Done()
		var wgTango sync.WaitGroup
		wgTango.Add(1)
		go StartTango(&wgTango, sfdl_file)
		wgTango.Wait()
		wgLoader.Wait()
	}
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

func StartTango(wgTango *sync.WaitGroup, sfdl_file string) {
	defer wgTango.Done()

	resetSFDLGlobals()
	resetFTPGlobals()
	gotErrors := 0

	_, chkerr := os.Stat(sfdl_file)
	if chkerr != nil {
		fmt.Printf("error: SFDL file error: %v\n", chkerr)
		AddLoaderLog(fmt.Sprintf("SFDL file error: %v\n", chkerr))
		gotErrors++
	}

	if gotErrors == 0 {
		err := OpenSFDL(sfdl_file, SFDLPassword)
		if err != nil {
			fmt.Printf("error: Unable to read/decrypt SFDL file! %v\n", err)
			AddLoaderLog(fmt.Sprintf("error: Unable to read/decrypt SFDL file! %v\n", err))
			gotErrors++
		}

		if gotErrors == 0 {

			fmt.Println("FTP Index for: " + Server_Name)
			AddLoaderLog("FTP Index for: " + Server_Name)

			for _, path := range Server_Path {
				var retryCounter = 0
				for {
					err = GetFTPIndex(path)
					if err != nil {
						newError := err.Error()
						if strings.HasPrefix(newError, "553") || strings.HasPrefix(newError, "530") || strings.HasPrefix(newError, "421") {
							if DEBUG {
								fmt.Println("ftp index error (pyro server?):", newError)
							}
							retryCounter++
							fmt.Printf("Retry [%d] FTP Index for: %s\n", retryCounter, newError)
							AddLoaderLog(fmt.Sprintf("Retry [%d] FTP Index for: %s\n", retryCounter, newError))
							time.Sleep(1 * time.Second)
						} else {
							gotErrors++
							break
						}
					} else {
						break
					}
				}
			}

			// extra check if we got any file(s) to download
			// without using error return on path index errors
			if len(Server_File) == 0 {
				gotErrors++
			}

			if gotErrors == 0 {
				if len(Server_File) < MaxConcurrentDownloads {
					MaxConcurrentDownloads = len(Server_File)
				}

				startTime := time.Now()

				fmt.Printf("Loading %d files (%s) using %d threads!\n", len(Server_File), FormatBytes(Download_Size), MaxConcurrentDownloads)
				AddLoaderLog(fmt.Sprintf("Loading %d files (%s) using %d threads!\n", len(Server_File), FormatBytes(Download_Size), MaxConcurrentDownloads))

				var retryCounter2 = 0
				for {
					err2 := InitializeFTPDownloads()
					if err2 != nil {
						newError := err2.Error()
						if strings.HasPrefix(newError, "553") || strings.HasPrefix(newError, "530") || strings.HasPrefix(newError, "421") {
							if DEBUG {
								fmt.Println("ftp download error (pyro server?):", newError)
							}
							retryCounter2++
							fmt.Printf("Retry [%d] FTP download: %s\n", retryCounter2, newError)
							AddLoaderLog(fmt.Sprintf("Retry [%d] FTP download: %s\n", retryCounter2, newError))
							time.Sleep(1 * time.Second)
						} else {
							fmt.Printf("error: FTP Download error: %s\n", newError)
							AddLoaderLog(fmt.Sprintf("error: FTP Download error: %s\n", newError))
							gotErrors++
							if UseWebserver {
								ProgressGlobals[0].Status = 3
							}
							break
						}
					} else {
						break
					}
				}

				if DownloadUserAbort {
					if DEBUG {
						fmt.Println("DownloadUserAbort: ", DownloadUserAbort)
					}
					gotErrors++
				}

				if gotErrors == 0 {
					if UseWebserver {
						ProgressGlobals[0].Status = 9
					}

					stopTime := time.Now()

					secondsLoaded := int(stopTime.Sub(startTime).Seconds())
					timeLoaded := formatDuration(secondsLoaded)

					fmt.Printf("Loaded %d files (%s) in %s\n", len(Server_File), FormatBytes(Download_Size), timeLoaded)
					AddLoaderLog(fmt.Sprintf("Loaded %d files (%s) in %s\n", len(Server_File), FormatBytes(Download_Size), timeLoaded))
					fmt.Println("Creating speedreport ...")
					AddLoaderLog("Creating speedreport ...")

					// create speedreport
					if Download_Size > 0 && uint64(secondsLoaded) > 0 {
						speed := FormatBytes(Download_Size / uint64(secondsLoaded))

						speedreportText := []string{
							"[B]" + Server_Name + "[/B]",
							"[HR][/HR]",
							"Upper: " + Server_Uppa,
							"Loaded " + strconv.Itoa(len(Server_File)) + " file(s) (" + FormatBytes(Download_Size) + ") in " + timeLoaded,
							"Speed: " + speed + "/s",
							"Threads used: " + strconv.Itoa(MaxConcurrentDownloads),
							"[HR][/HR]",
							" ",
							"[URL=\"https://mlcboard.com/forum/showthread.php?612810\"][I][SIZE=1]goSFDLSauger v" + VERSION + "[/SIZE][/I][/URL]",
						}

						errSpeed := createSpeedReport(RemoveDuplicateSlashes(DestinationDownloadPath+"/"+Server_Name+"/speedreport.txt"), speedreportText)
						if errSpeed != nil {
							fmt.Printf("Error creating speedreport file: %v\n", errSpeed)
							AddLoaderLog(fmt.Sprintf("Error creating speedreport file: %v\n", errSpeed))
						}
					} else {
						gotErrors++
					}

					dirPath := filepath.Dir(sfdl_file)
					if gotErrors == 0 {
						fmt.Println("Moving SFDL file to download path ...")
						AddLoaderLog("Moving SFDL file to download path ...")
						sfdl_from := sfdl_file
						sfdl_to := RemoveDuplicateSlashes(DestinationDownloadPath + "/" + Server_Name + "/" + filepath.Base(sfdl_file))
						err3 := os.Rename(sfdl_from, sfdl_to)
						if err3 != nil {
							fmt.Println("Error moving SFDL file! ", err)
							AddLoaderLog(fmt.Sprintf("Error moving SFDL file! %s", err))
							gotErrors++
						}
					}

					if gotErrors == 0 {
						if UseUNRARUnZIP {
							fmt.Println("Unpacking ZIP and RAR files ...")
							AddLoaderLog("Unpacking ZIP and RAR files ...")
							dir := RemoveDuplicateSlashes(DestinationDownloadPath + "/" + Server_Name + "/")

							// get all (sub) direktories
							folders, err := GetAllSubs(dir)
							if err != nil {
								fmt.Println("Unpacker Error:", err)
								AddLoaderLog(fmt.Sprintf("Unpacker Error: %s", err))
							}
							for _, folder := range folders {
								MrUnpacker(folder, folder)
							}
						}
					}

					if gotErrors == 0 {
						FillSFDLFilesArray(dirPath, "")
					} else {
						SFDL_Files = removeSFDLFile(SFDL_Files, sfdl_file) // remove sfdl from list
						FillSFDLFilesArray(dirPath, sfdl_file)
					}
				}
			}
		}
	}

	time.Sleep(2 * time.Second)
	resetSFDLGlobals()
	resetFTPGlobals()
	DownloadLogs = []string{}
	time.Sleep(1 * time.Second)

	if gotErrors != 0 {
		SFDL_Files = removeSFDLFile(SFDL_Files, sfdl_file) // remove sfdl from list
	} else {
		newMsg := "successfully downloaded: " + filepath.Base(sfdl_file)
		fmt.Println(newMsg)
		AddLoaderLog(newMsg)
	}

	if len(SFDL_Files) > 0 {
		next_sfdl_file := SFDL_Files[0]
		if next_sfdl_file != "" {
			clearConsole()
			fmt.Println("goSFDLSauger v" + VERSION + " (GrafSauger)")
			printLogo()
			fmt.Println("SFDL: " + next_sfdl_file)
			AddLoaderLog("SFDL: " + next_sfdl_file)
			isDownloadRunning = false
			startLoaderFunctions(next_sfdl_file)
		}
	} else {
		fmt.Println("There is nothing more to do!")
		AddLoaderLog("There is nothing more to do!")
		isDownloadRunning = false
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
		AddLoaderLog(fmt.Sprintf("Error finding local path: %s", err))
		return "", err
	}
	return currentPath, nil
}

func removeSFDLFile(slice []string, element string) []string {
	index := -1
	for i, v := range slice {
		if v == element {
			index = i
			break
		}
	}

	if index == -1 {
		return slice
	}

	return append(slice[:index], slice[index+1:]...)
}

func FillSFDLFilesArray(sfdl_files_path, ignoreSFDL string) {
	SFDL_Files = SFDL_Files[:0]
	entries, err := os.ReadDir(sfdl_files_path)
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sfdl") {
			if entry.Name() != ignoreSFDL {
				SFDL_Files = append(SFDL_Files, filepath.Join(sfdl_files_path, entry.Name()))
			}
		}
	}
}

func formatDuration(seconds int) string {
	if seconds < 0 {
		return "minus time"
	}
	days := seconds / (60 * 60 * 24)
	seconds %= 60 * 60 * 24
	hours := seconds / (60 * 60)
	seconds %= 60 * 60
	minutes := seconds / 60
	seconds %= 60
	parts := []string{}
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%d days", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%d hours", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%d minutes", minutes))
	}
	if seconds > 0 {
		parts = append(parts, fmt.Sprintf("%d seconds", seconds))
	}
	return join(parts, ", ")
}

func join(parts []string, sep string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	default:
		return parts[0] + sep + join(parts[1:], sep)
	}
}

func createSpeedReport(filePath string, lines []string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, line := range lines {
		_, err := file.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}
	return nil
}

func AddLoaderLog(logLine string) {
	LoaderLogs = append(LoaderLogs, "["+time.Now().Format("2006-01-02 15:04:05")+"] "+logLine)
	DownloadLogs = append(DownloadLogs, "["+time.Now().Format("2006-01-02 15:04:05")+"] "+logLine)
	if UseMQTT {
		SendMQTTMsg(logLine, "logs")
	}
}
