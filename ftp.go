package main

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/jlaffaye/ftp"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

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
var progessFiles []ProgressFile

func GetFTPIndex(ftp_path string) error {
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

	defer ftpClient.Quit()
	return nil
}

func listFilesRecursive(ftpClient *ftp.ServerConn, path string, fileList *[]string) error {
	err := ftpClient.ChangeDir(path)
	if err != nil {
		fmt.Println("FTP Error: ChangeDir failed: ", err)
	} else {
		entries, err := ftpClient.List("")
		if err != nil {
			fmt.Println("FTP Error: List failed: ", err)
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

func StartFTPDownloads() error {
	p := mpb.New(
		mpb.WithOutput(os.Stdout),
	)

	downloadQueue := make(chan string, MaxConcurrentDownloads)
	var wg sync.WaitGroup

	for i := 0; i < MaxConcurrentDownloads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filename := range downloadQueue {
				err := downloadFile(filename, DestinationDownloadPath, p)
				if err != nil {
					fmt.Printf("Error loading file %s: %v\n", returnFilePathWithoutBytes(filename), err)
				}
			}
		}()
	}

	for _, file := range Server_File {
		downloadQueue <- file
	}
	close(downloadQueue)

	wg.Wait()

	return nil
}

func downloadFile(filename string, downloadDirectory string, p *mpb.Progress) error {
	ftpAddress := fmt.Sprintf("%s:%d", Server_Host, Server_Port)
	ftpClient, err := ftp.Dial(ftpAddress)
	if err != nil {
		return err
	}

	err = ftpClient.Login(Server_User, Server_Pass)
	if err != nil {
		return err
	}
	defer ftpClient.Quit()

	fileSize := returnFileSizeInUnit64(filename)

	fileInclSubPath := returnSubPath(filename, Server_Name)
	if fileInclSubPath == "" {
		fileInclSubPath = filepath.Base(filename)
	}
	fullLocalDownloadFilePath := RemoveDuplicateSlashes(downloadDirectory + "/" + Server_Name + "/" + fileInclSubPath)

	if DEBUG {
		fmt.Printf("fileSize: %d\n", fileSize)
		fmt.Printf("fullLocalDownloadFilePath: %s\n", fullLocalDownloadFilePath)
		fmt.Printf("filepath (without bytes): %s\n", returnFilePathWithoutBytes(filename))
		fmt.Printf("filename only: %s\n", returnFilePathWithoutBytes(path.Base(filename)))
	}

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

	if DEBUG {
		fmt.Printf("downloadedSize: %d\n", downloadedSize)
		fmt.Printf("fileSize: %d\n", fileSize)
	}

	var remoteFile *ftp.Response
	if downloadedSize < int64(fileSize) {
		remoteFile, err = ftpClient.RetrFrom(returnFilePathWithoutBytes(filename), uint64(downloadedSize))
		if err != nil {
			return err
		}
		defer remoteFile.Close()
	}

	bar := p.AddBar(int64(fileSize),
		mpb.PrependDecorators(
			decor.Name(path.Base(returnFilePathWithoutBytes(filename))),
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

	if downloadedSize < int64(fileSize) {
		progressWriter.bar.SetCurrent(downloadedSize)
		_, err = io.Copy(progressWriter, remoteFile)
		if err != nil {
			return err
		}
	} else {
		bar.SetTotal(int64(fileSize), true)
		progressWriter.bar.SetCurrent(int64(fileSize))
	}

	return nil
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n, err := pw.writer.Write(p)
	pw.downloaded += uint64(n)
	progress := float64(pw.downloaded) / float64(pw.total) * 100

	pw.bar.IncrBy(n)

	if nameExists(progessFiles, path.Base(pw.filename)) {
		updateFileByName(progessFiles, path.Base(pw.filename), pw.downloaded, progress, 1)
	} else {
		progessFiles = append(progessFiles,
			ProgressFile{Name: path.Base(pw.filename),
				Total:    pw.total,
				Loaded:   pw.downloaded,
				Progress: progress,
				Status:   1})
	}
	return n, err
}

func updateFileByName(files []ProgressFile, name string, downloaded uint64, newSize float64, status int) bool {
	for i, file := range files {
		if file.Name == name {
			files[i].Progress = newSize
			if downloaded <= file.Total {
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
		panic("Error: Unknown file string format!")
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
