package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jlaffaye/ftp"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

type ProgressGlobal struct {
	Name     string
	Total    uint64
	Loaded   uint64
	Progress float64
	Status   int
}

type ProgressFile struct {
	Name     string
	Total    uint64
	Loaded   uint64
	Progress float64
	Status   int
}

type progressWriter struct {
	writer     io.Writer
	total      uint64
	downloaded uint64
	filename   string
	bar        *mpb.Bar
}

var Server_File []string
var ProgressGlobals []ProgressGlobal
var ProgessFiles []ProgressFile
var progressUpdateTime time.Time
var ftpConnections = make(map[string]context.CancelFunc)
var ftpMutex sync.Mutex
var globalCancel context.CancelFunc
var downloadQueue chan string
var DownloadUserAbort bool = false

func resetFTPGlobals() {
	Download_Size = 0
	Server_File = []string{}
	ProgressGlobals = []ProgressGlobal{}
	ProgessFiles = []ProgressFile{}
	DownloadUserAbort = false
	for key := range ftpConnections {
		delete(ftpConnections, key)
	}
	ftpMutex = sync.Mutex{}
	globalCancel = nil
	downloadQueue = nil
}

func GetFTPIndex(ftp_path string) error {
	resetFTPGlobals()

	ftpAddress := fmt.Sprintf("%s:%d", Server_Host, Server_Port)
	ftpClient, err := ftp.Dial(ftpAddress)
	if err != nil {
		fmt.Println("Error: FTP Server: ", err)
		return err
	}

	err = ftpClient.Login(Server_User, Server_Pass)
	if err != nil {
		fmt.Println("Error: FTP Server LogIn: ", err)
		return err
	}

	err = listFilesRecursive(ftpClient, ftp_path, &Server_File)
	if err != nil {
		fmt.Println("Error: FTP Unable to list files!", err)
		return err
	}

	if DEBUG {
		for _, file := range Server_File {
			fmt.Printf("Server_File(s): %s\n", file)
		}
	}

	totalDownload := uint64(0)

	for _, file := range Server_File {
		ProgessFiles = append(ProgessFiles,
			ProgressFile{
				Name:     returnFilePathWithoutBytes(path.Base(file)),
				Total:    returnFileSizeInUnit64(file),
				Loaded:   0,
				Progress: 0.0,
				Status:   0})

		totalDownload += returnFileSizeInUnit64(file)
	}

	ProgressGlobals = append(ProgressGlobals,
		ProgressGlobal{
			Name:     Server_Name,
			Total:    totalDownload,
			Loaded:   0,
			Progress: 0.0,
			Status:   0})

	defer ftpClient.Quit()
	return nil
}

func listFilesRecursive(ftpClient *ftp.ServerConn, path string, fileList *[]string) error {
	err := ftpClient.ChangeDir(path)
	if err != nil {
		fmt.Println("FTP Error: ChangeDir failed:", err)
		AddLoaderLog(fmt.Sprintln("FTP Error: ChangeDir failed:", err))
	} else {
		entries, err := ftpClient.List("")
		if err != nil {
			fmt.Println("FTP Error: List failed:", err)
			AddLoaderLog(fmt.Sprintln("FTP Error: List failed:", err))
		} else {
			for _, entry := range entries {
				if entry.Type == ftp.EntryTypeFile {
					Download_Size += entry.Size
					fileString := path + entry.Name + ";;;" + strconv.FormatUint(entry.Size, 10)
					*fileList = append(*fileList, fileString)
				} else if entry.Type == ftp.EntryTypeFolder {
					newPath := RemoveDuplicateSlashes(path + entry.Name + "/")
					err := listFilesRecursive(ftpClient, newPath, fileList)
					if err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func InitializeFTPDownloads() error {
	ctxStartFTP, cancelFTP := context.WithCancel(context.Background())
	globalCancel = cancelFTP
	return StartFTPDownloads(ctxStartFTP)
}

func StartFTPDownloads(ctxFTP context.Context) error {
	p := mpb.New(
		mpb.WithOutput(os.Stdout),
	)

	if downloadQueue == nil {
		downloadQueue = make(chan string, MaxConcurrentDownloads)
	}

	var wgFTP sync.WaitGroup

	for i := 0; i < MaxConcurrentDownloads; i++ {
		wgFTP.Add(1)
		go func(workerID int) {
			defer wgFTP.Done()
			if DEBUG {
				fmt.Printf("Worker %d started\n", workerID)
			}
			for {
				select {
				case <-ctxFTP.Done():
					if DEBUG {
						fmt.Printf("Worker %d stopping due to cancellation.\n", workerID)
					}
					return
				case filename, ok := <-downloadQueue:
					if !ok {
						return
					}
					err := downloadFileWithContext(filename, DestinationDownloadPath, p)
					if err != nil && err != io.EOF {
						fmt.Printf("Error loading file %s: %v\n", filepath.Base(returnFilePathWithoutBytes(filename)), err)
						AddLoaderLog(fmt.Sprintf("Error loading file %s: %v\n", filepath.Base(returnFilePathWithoutBytes(filename)), err))
					} else {
						AddLoaderLog(filepath.Base(returnFilePathWithoutBytes(filename)) + " - done!")
					}
				}
			}
		}(i)
	}

	for _, file := range Server_File {
		select {
		case <-ctxFTP.Done():
			fmt.Println("Download queue processing stopped.")
			if downloadQueue != nil {
				close(downloadQueue)
			}
			wgFTP.Wait()
			return fmt.Errorf("downloads stopped")
		case downloadQueue <- file:
			// skip on user cancellation
		}
	}

	close(downloadQueue)
	wgFTP.Wait()
	return nil
}

func StopAllFTPDownloads() {
	DownloadUserAbort = true

	defer func() {
		if r := recover(); r != nil {
			if DEBUG {
				fmt.Println("Catch panic:", r)
			}
		}
	}()

	if isDownloadRunning {
		AddLoaderLog("Stopping all downloads!")

		if globalCancel != nil {
			globalCancel()
		}

		ftpMutex.Lock()

		for id, cancel := range ftpConnections {
			cancel()
			delete(ftpConnections, id)
			fmt.Printf("Download for %s stopped.\n", filepath.Base(returnFilePathWithoutBytes(id)))
			AddLoaderLog(fmt.Sprintf("Download for %s stopped.\n", filepath.Base(returnFilePathWithoutBytes(id))))
		}

		if downloadQueue != nil {
			func() {
				defer func() {
					if r := recover(); r != nil {
						if DEBUG {
							fmt.Println("Catch panic on chan close:", r)
						}
					}
				}()
				close(downloadQueue)
				downloadQueue = nil
			}()
		}

		ftpMutex.Unlock()

		fmt.Println("All downloads stopped.")
		AddLoaderLog("All downloads stopped.")
		isDownloadRunning = false
	}
}

func downloadFileWithContext(filename string, downloadDirectory string, p *mpb.Progress) error {
	ctx, cancel := context.WithCancel(context.Background())

	ftpMutex.Lock()
	ftpConnections[filename] = cancel
	ftpMutex.Unlock()
	defer func() {
		ftpMutex.Lock()
		delete(ftpConnections, filename)
		ftpMutex.Unlock()
	}()

	ftpAddress := fmt.Sprintf("%s:%d", Server_Host, Server_Port)
	ftpClient, err := ftp.Dial(ftpAddress, ftp.DialWithContext(ctx))
	if err != nil {
		return err
	}
	defer ftpClient.Quit()

	err = ftpClient.Login(Server_User, Server_Pass)
	if err != nil {
		return err
	}

	fileSize := returnFileSizeInUnit64(filename)
	fileInclSubPath := returnSubPath(filename, Server_Name)
	if fileInclSubPath == "" {
		fileInclSubPath = filepath.Base(filename)
	}
	fullLocalDownloadFilePath := RemoveDuplicateSlashes(downloadDirectory + "/" + Server_Name + "/" + fileInclSubPath)

	dir := filepath.Dir(fullLocalDownloadFilePath)
	err = os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		fmt.Println("Error: Unable to create dir! ", err)
		return err
	}

	var localFile *os.File
	var downloadedSize int64

	if _, err := os.Stat(fullLocalDownloadFilePath); err == nil {
		localFile, err = os.OpenFile(fullLocalDownloadFilePath, os.O_APPEND|os.O_WRONLY, os.ModePerm)
		if err != nil {
			return err
		}
		downloadedSize, err = localFile.Seek(0, io.SeekEnd)
		if err != nil {
			return err
		}
	} else {
		localFile, err = os.Create(fullLocalDownloadFilePath)
		if err != nil {
			return err
		}
		downloadedSize = 0
	}
	defer localFile.Close()

	if downloadedSize < int64(fileSize) {
		AddLoaderLog("Downloading now: " + filepath.Base(returnFilePathWithoutBytes(filename)))

		remoteFile, err := ftpClient.RetrFrom(returnFilePathWithoutBytes(filename), uint64(downloadedSize))
		if err != nil {
			return err
		}
		defer remoteFile.Close()

		bar := p.AddBar(int64(fileSize), mpb.BarRemoveOnComplete(),
			mpb.PrependDecorators(
				decor.Name(filepath.Base(returnFilePathWithoutBytes(filename))),
				decor.AverageSpeed(decor.SizeB1000(0), "(% .2f)", decor.WCSyncSpace),
			),
			mpb.AppendDecorators(
				decor.Counters(decor.SizeB1000(0), "[% .2f/% .2f]", decor.WCSyncSpace),
				decor.OnComplete(decor.NewPercentage("%d", decor.WCSyncSpace), "done"),
			),
		)

		progressWriter := &progressWriter{
			writer:     localFile,
			total:      fileSize,
			downloaded: uint64(downloadedSize),
			filename:   returnFilePathWithoutBytes(filename),
			bar:        bar,
		}

		// set progress for files on resume
		progressWriter.bar.SetCurrent(int64(downloadedSize))

		buffer := make([]byte, 32*1024)
		for {
			select {
			case <-ctx.Done():
				bar.Abort(true)
				ftpClient.Quit()
				if DEBUG {
					fmt.Printf("Download for %s cancelled.\n", filepath.Base(returnFilePathWithoutBytes(filename)))
				}
				return fmt.Errorf("download cancelled")
			default:
				n, readErr := remoteFile.Read(buffer)
				if n > 0 {
					_, writeErr := progressWriter.Write(buffer[:n])
					if writeErr != nil {
						return writeErr
					}
				}
				if readErr == io.EOF {
					return readErr
				}
				if readErr != nil {
					return readErr
				}
			}
		}
	} else {
		bar := p.AddBar(int64(fileSize), mpb.BarRemoveOnComplete())
		bar.SetTotal(int64(fileSize), true)
		progressWriter := &progressWriter{
			bar: bar,
		}
		progressWriter.bar.SetCurrent(int64(fileSize))
		bar.Completed()

		if UseWebserver {
			updateFileByName(ProgessFiles, filepath.Base(returnFilePathWithoutBytes(filename)), fileSize, 100, 9)
		}

		AddLoaderLog(filepath.Base(returnFilePathWithoutBytes(filename)) + " - done!")
	}

	return nil
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n, err := pw.writer.Write(p)
	pw.downloaded += uint64(n)
	progress := float64(pw.downloaded) / float64(pw.total) * 100

	pw.bar.IncrBy(n)

	if UseWebserver {
		if nameExists(ProgessFiles, path.Base(pw.filename)) {
			updateFileByName(ProgessFiles, path.Base(pw.filename), pw.downloaded, progress, 1)
		} else {
			ProgessFiles = append(ProgessFiles,
				ProgressFile{Name: path.Base(pw.filename),
					Total:    pw.total,
					Loaded:   pw.downloaded,
					Progress: progress,
					Status:   1})
		}

		// get total download progress
		totalDL := uint64(0)
		for _, file := range ProgessFiles {
			totalDL += file.Loaded
		}

		ProgressGlobals[0].Loaded = totalDL
		if ProgressGlobals[0].Total != 0 {
			ProgressGlobals[0].Progress = (float64(totalDL) / float64(ProgressGlobals[0].Total)) * 100
		}

		if totalDL == ProgressGlobals[0].Total {
			ProgressGlobals[0].Status = 9
		} else {
			ProgressGlobals[0].Status = 1
		}

		if DEBUG {
			if time.Since(progressUpdateTime) >= time.Second {
				for _, progress := range ProgessFiles {
					fmt.Printf("Name: %s, Total: %d, Loaded: %d, Progress: %.2f%%, Status: %d\n",
						progress.Name, progress.Total, progress.Loaded, progress.Progress, progress.Status)
				}
				progressUpdateTime = time.Now()
			}
		}
	}

	if progress == 100 {
		pw.bar.Completed()
	}

	return n, err
}

func updateFileByName(files []ProgressFile, name string, downloaded uint64, newSize float64, status int) bool {
	for i, file := range files {
		if file.Name == name {
			files[i].Loaded = downloaded
			files[i].Progress = newSize
			if newSize == 100.0 {
				files[i].Status = 9
			} else {
				files[i].Status = status
			}
			return true
		}
	}
	return false
}

func nameExists(files []ProgressFile, name string) bool {
	for _, file := range files {
		if file.Name == name {
			return true
		}
	}
	return false
}

func RemoveDuplicateSlashes(s string) string {
	var result strings.Builder
	prevSlash := false

	for _, char := range s {
		if char == '/' {
			if !prevSlash {
				result.WriteRune(char)
			}
			prevSlash = true
		} else {
			result.WriteRune(char)
			prevSlash = false
		}
	}

	return result.String()
}

func returnSubPath(path string, name string) string {
	parts := strings.Split(path, ";;;")
	if len(parts) != 2 {
		fmt.Println("Error: Unknown file string format!")
		return ""
	}

	index := strings.Index(parts[0], name)
	if index != -1 {
		result := parts[0][index+len(name):]
		return result
	}

	return ""
}

func returnFileSizeInUnit64(path string) uint64 {
	parts := strings.Split(path, ";;;")
	if len(parts) != 2 {
		panic("Error: Unknown file string format [2]!")
	}

	bytesStr := parts[1]

	bytes, err := strconv.ParseUint(bytesStr, 10, 64)
	if err != nil {
		fmt.Println("Error: Unable to convert file byte string to uint64!", err)
		panic(err)
	}

	return bytes
}

func returnFilePathWithoutBytes(path string) string {
	parts := strings.Split(path, ";;;")
	if len(parts) != 2 {
		panic("Error: Unknown file string format!")
	}
	return parts[0]
}
