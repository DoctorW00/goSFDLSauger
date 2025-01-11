package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/nwaples/rardecode"
)

func findMainRarFile(dir string) (string, error) {
	rarPattern := regexp.MustCompile(`(?i)\.rar$|part0*1\.rar$|part1\.rar$`)
	files, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("error unable to read path: %v", err)
	}

	for _, file := range files {
		if rarPattern.MatchString(file.Name()) {
			return filepath.Join(dir, file.Name()), nil
		}
	}
	return "", fmt.Errorf("error: no main rar file found")
}

func findAllRarFiles(dir string) ([]string, error) {
	rarPattern := regexp.MustCompile(`(?i)^.*\.([r-zR-Z])\d+$|(?i)^.*\.rar$`)
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("error unable to read path: %v", err)
	}
	var rarFiles []string
	for _, file := range files {
		if !file.IsDir() && rarPattern.MatchString(file.Name()) {
			rarFiles = append(rarFiles, filepath.Join(dir, file.Name()))
		}
	}
	return rarFiles, nil
}

func findZipFiles(dir string) ([]string, error) {
	var zipFiles []string
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("error unable to read path: %v", err)
	}
	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".zip" {
			zipFiles = append(zipFiles, filepath.Join(dir, file.Name()))
		}
	}
	return zipFiles, nil
}

func deleteFiles(files []string) error {
	for _, file := range files {
		err := os.Remove(file)
		if err != nil {
			return fmt.Errorf("error removing %s: %w", file, err)
		}
	}
	return nil
}

func GetAllSubs(root string) ([]string, error) {
	var folders []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			folders = append(folders, path)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return folders, nil
}

func Unzip(src string, dest string) error {
	zipFile, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("error opening ZIP file: %w", err)
	}
	defer zipFile.Close()

	for _, file := range zipFile.File {
		if err := extractZipFile(file, dest); err != nil {
			return fmt.Errorf("error extracting file %s: %w", file.Name, err)
		}
	}
	return nil
}

func extractZipFile(file *zip.File, dest string) error {
	zipFileReader, err := file.Open()
	if err != nil {
		return fmt.Errorf("error opening ZIP file: %s: %w", file.Name, err)
	}
	defer zipFileReader.Close()

	path := filepath.Join(dest, file.Name)

	if file.FileInfo().IsDir() {
		return os.MkdirAll(path, os.ModePerm)
	}

	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return fmt.Errorf("error creating path for %s: %w", path, err)
	}

	outFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("error creating file for %s: %w", path, err)
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, zipFileReader)
	if err != nil {
		return fmt.Errorf("error copy file %s: %w", path, err)
	}

	return nil
}

func Unrar(src string, dest string) error {
	rarReader, err := rardecode.OpenReader(src, "")
	if err != nil {
		return fmt.Errorf("error opening RAR file: %w", err)
	}
	defer rarReader.Close()

	for {
		header, err := rarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading RAR file: %w", err)
		}

		if err := extractRarFile(header, rarReader, dest); err != nil {
			return fmt.Errorf("error extracting file %s: %w", header.Name, err)
		}
	}

	return nil
}

func extractRarFile(header *rardecode.FileHeader, r io.Reader, dest string) error {
	path := filepath.Join(dest, header.Name)

	if header.IsDir {
		return os.MkdirAll(path, os.ModePerm)
	}

	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return fmt.Errorf("error creating path for %s: %w", path, err)
	}

	outFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("error creating file %s: %w", path, err)
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, r)
	if err != nil {
		return fmt.Errorf("error copy file %s: %w", path, err)
	}

	return nil
}

func Unpack(src string, dest string) error {
	switch filepath.Ext(src) {
	case ".zip":
		return Unzip(src, dest)
	case ".rar":
		return Unrar(src, dest)
	default:
		return fmt.Errorf("unpack: error not supported file type %s", filepath.Ext(src))
	}
}

func MrUnpacker(src string, dest string) {
	// recall MrUnpacker to check for more files
	recallMrUnpacker := false

	// check for .zip files first
	zipFiles, _ := findZipFiles(src)
	if len(zipFiles) > 0 {
		recallMrUnpacker = true
		deleteAllZipFiles := true

		for _, zipFile := range zipFiles {
			if err := Unpack(zipFile, dest); err != nil {
				fmt.Println("unpack ZIP error: ", err)
				AddLoaderLog("unpack ZIP error: " + err.Error())
				recallMrUnpacker = false
				deleteAllZipFiles = false
			} else {
				fmt.Printf("unpacking ZIP %s was successfuly!\n", zipFile)
				AddLoaderLog(fmt.Sprintf("unpacking ZIP %s was successfuly!", zipFile))
			}
		}

		// delete all zip files now
		if deleteAllZipFiles {
			AddLoaderLog("deleting ZIP files ...")
			err := deleteFiles(zipFiles)
			if err != nil {
				fmt.Printf("error removing: %v\n", err)
				AddLoaderLog(fmt.Sprintf("error removing: %v", err))
				recallMrUnpacker = false
			} else {
				fmt.Println("all zip files removed!")
				AddLoaderLog("all zip files removed!")
			}
		}
	}

	// get all rar files
	rarFiles, _ := findAllRarFiles(src)
	if len(rarFiles) > 0 {
		recallMrUnpacker = true
		// check if we got a main rar file
		mainRARFile, _ := findMainRarFile(src)
		if mainRARFile != "" {
			if err := Unpack(mainRARFile, dest); err != nil {
				fmt.Println("unpack RAR error: ", err)
				AddLoaderLog("unpack RAR error: " + err.Error())
				recallMrUnpacker = false
			} else {
				fmt.Println("unpacking RAR file(s) was successfuly!")
				AddLoaderLog("unpacking RAR file(s) was successfuly!")
				// delete all rar files now
				err := deleteFiles(rarFiles)
				if err != nil {
					fmt.Printf("error removing: %v\n", err)
					AddLoaderLog(fmt.Sprintf("error removing: %v", err))
					recallMrUnpacker = false
				} else {
					fmt.Println("all rar files removed!")
					AddLoaderLog("all rar files removed!")
				}
			}
		}
	}

	if recallMrUnpacker {
		MrUnpacker(src, dest)
	}
}
