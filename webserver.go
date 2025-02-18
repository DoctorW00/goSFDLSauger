package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"math/big"
	mathRand "math/rand"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

var WWWServerPort = 8080
var WWWServerIP = ""

var WWWRateLimit = rate.Every(time.Second / 2)
var WWWRateLimit_Times = 5

var sessions = make(map[string]Session)
var UserHomeDir = "."
var UserDownloadDir = ""

const passwordLength = 32

var passwordFile = "webgui_password.txt"
var loginData = ""

var superSalt = "WrFESjTOcp0Z7g3"

//go:embed www/**
var content embed.FS

type Session struct {
	IsLoggedIn bool
	CSRFToken  string
}

type Server struct {
	Addr    string
	TLSCert string
	TLSKey  string
	UseTLS  bool
	quitCh  chan bool
}

type CertManager struct {
	CertFile string
	KeyFile  string
}

type File struct {
	Name  string
	IsDir bool
	Path  string
	Size  string
	CSRF  string
}

type ServerResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func getContentType(filePath string) string {
	switch {
	case strings.HasSuffix(filePath, ".html"):
		return "text/html"
	case strings.HasSuffix(filePath, ".css"):
		return "text/css"
	case strings.HasSuffix(filePath, ".js"):
		return "application/javascript"
	case strings.HasSuffix(filePath, ".png"):
		return "image/png"
	case strings.HasSuffix(filePath, ".jpg"), strings.HasSuffix(filePath, ".jpeg"):
		return "image/jpeg"
	case strings.HasSuffix(filePath, ".gif"):
		return "image/gif"
	case strings.HasSuffix(filePath, ".ico"):
		return "image/x-icon"
	case strings.HasSuffix(filePath, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(filePath, ".webp"):
		return "image/webp"
	case strings.HasSuffix(filePath, ".bmp"):
		return "image/bmp"
	case strings.HasSuffix(filePath, ".tiff"), strings.HasSuffix(filePath, ".tif"):
		return "image/tiff"
	case strings.HasSuffix(filePath, ".mp4"):
		return "video/mp4"
	case strings.HasSuffix(filePath, ".ogg"):
		return "audio/ogg"
	case strings.HasSuffix(filePath, ".mp3"):
		return "audio/mpeg"
	case strings.HasSuffix(filePath, ".wav"):
		return "audio/wav"
	case strings.HasSuffix(filePath, ".flac"):
		return "audio/flac"
	case strings.HasSuffix(filePath, ".aac"):
		return "audio/aac"
	case strings.HasSuffix(filePath, ".woff"), strings.HasSuffix(filePath, ".woff2"):
		return "font/woff"
	case strings.HasSuffix(filePath, ".otf"):
		return "font/otf"
	case strings.HasSuffix(filePath, ".ttf"):
		return "font/ttf"
	case strings.HasSuffix(filePath, ".eot"):
		return "application/vnd.ms-fontobject"
	case strings.HasSuffix(filePath, ".json"):
		return "application/json"
	case strings.HasSuffix(filePath, ".json5"):
		return "application/json"
	case strings.HasSuffix(filePath, ".xml"):
		return "application/xml"
	case strings.HasSuffix(filePath, ".txt"):
		return "text/plain"
	case strings.HasSuffix(filePath, ".nfo"):
		return "text/plain"
	case strings.HasSuffix(filePath, ".csv"):
		return "text/csv"
	case strings.HasSuffix(filePath, ".md"):
		return "text/markdown"
	case strings.HasSuffix(filePath, ".log"):
		return "text/plain"
	case strings.HasSuffix(filePath, ".pdf"):
		return "application/pdf"
	case strings.HasSuffix(filePath, ".zip"):
		return "application/zip"
	case strings.HasSuffix(filePath, ".rar"):
		return "application/x-rar-compressed"
	case strings.HasSuffix(filePath, ".7z"):
		return "application/x-7z-compressed"
	case strings.HasSuffix(filePath, ".tar"):
		return "application/x-tar"
	case strings.HasSuffix(filePath, ".tar.gz"), strings.HasSuffix(filePath, ".tgz"):
		return "application/gzip"
	case strings.HasSuffix(filePath, ".tar.bz2"):
		return "application/x-bzip2"
	case strings.HasSuffix(filePath, ".tar.xz"):
		return "application/x-xz"
	case strings.HasSuffix(filePath, ".ejs"):
		return "text/html"
	case strings.HasSuffix(filePath, ".handlebars"), strings.HasSuffix(filePath, ".hbs"):
		return "text/html"
	case strings.HasSuffix(filePath, ".avi"):
		return "video/x-msvideo"
	case strings.HasSuffix(filePath, ".mov"):
		return "video/quicktime"
	case strings.HasSuffix(filePath, ".webm"):
		return "video/webm"
	default:
		return "application/octet-stream"
	}
}

func NewServer(addr, cert, key string) *Server {
	useTLS := false
	if cert != "" && key != "" {
		var certFile string
		var keyFile string
		if UseConfig {
			if config.WebServer.UseSSL {
				certFile = filepath.Join(config.WebServer.SSLCertPath)
				keyFile = filepath.Join(config.WebServer.SSLKeyPath)
			}
		} else {
			certFile = filepath.Join(UserHomeDir, cert)
			keyFile = filepath.Join(UserHomeDir, key)
		}
		_, certErr := os.Stat(certFile)
		_, keyErr := os.Stat(keyFile)
		if certErr == nil && keyErr == nil {
			useTLS = true
			if UseConfig {
				useTLS = config.WebServer.UseSSL
			}
		} else {
			if UseConfig && config.WebServer.UseSSL {
				if fileExists(config.WebServer.SSLCertPath) && fileExists(config.WebServer.SSLKeyPath) {
					certFile = config.WebServer.SSLCertPath
					keyFile = config.WebServer.SSLKeyPath
				} else {
					certFile = path.Join(UserHomeDir, "server.crt")
					keyFile = path.Join(UserHomeDir, "server.key")
				}
			}
			certManager := NewCertManager(certFile, keyFile)
			if err := certManager.GenerateSelfSignedCert(); err != nil {
				fmt.Printf("error creating certificate files for webserver: %v\n", err)
				fmt.Println("running webserver without encryption!")
			} else {
				useTLS = true
				if UseConfig {
					useTLS = config.WebServer.UseSSL
				}
			}
		}
	}

	return &Server{
		Addr:    addr,
		TLSCert: cert,
		TLSKey:  key,
		UseTLS:  useTLS,
		quitCh:  make(chan bool),
	}
}

func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", contentHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.HandleFunc("/events", eventsHandler)
	mux.HandleFunc("/change-password", changePasswordHandler)
	mux.HandleFunc("/upload", uploadHandler)
	mux.HandleFunc("/files", fileHandler)
	mux.HandleFunc("/logs", logsHandler)
	mux.HandleFunc("/delete", deleteHandler)
	mux.HandleFunc("/config", configHandler)
	mux.HandleFunc("/config-update", configUpdateHandler)
	mux.HandleFunc("/sendMQTT", sendMQTTHandler)
	mux.HandleFunc("/start-stop-status", func(w http.ResponseWriter, r *http.Request) {
		if !IsUserLoggedIn(w, r, false) {
			return
		}
		if isDownloadRunning {
			sendServerResponseJson("isDownloadRunning", "true", w, http.StatusOK)
		} else {
			sendServerResponseJson("isDownloadRunning", "false", w, http.StatusOK)
		}
	})
	mux.HandleFunc("/stop-downloads", func(w http.ResponseWriter, r *http.Request) {
		if !IsUserLoggedIn(w, r, false) {
			return
		}
		if !isDownloadRunning {
			sendServerResponseJson("error", "there are no aktive downloads to stop!", w, http.StatusOK)
			AddLoaderLog("error: there are no aktive downloads to stop!")
			return
		}
		sendServerResponseJson("success", "stopping all downloads", w, http.StatusOK)
		AddLoaderLog("Stopping all downloads!")
		if UseMQTT {
			go SendMQTTMsg("Stopping all downloads!", "command", "stop")
		}
		go StopAllFTPDownloads()
	})
	mux.HandleFunc("/start-downloads", func(w http.ResponseWriter, r *http.Request) {
		if !IsUserLoggedIn(w, r, false) {
			return
		}
		if isDownloadRunning {
			sendServerResponseJson("error", "there is an aktive download running!", w, http.StatusOK)
			AddLoaderLog("error: there is an aktive download running!")
			return
		}
		sendServerResponseJson("success", "starting all downloads", w, http.StatusOK)
		AddLoaderLog("Starting all downloads!")
		if UseMQTT {
			SendMQTTMsg("Starting all downloads!", "command", "start")
		}
		go func() {
			FillSFDLFilesArray(filepath.Join(UserDownloadDir, "/sfdl_files"), "")
			if DEBUG {
				fmt.Println("/start-downloads")
				fmt.Println("SFDL_Files len:", len(SFDL_Files))
			}
			if len(SFDL_Files) > 0 {
				sfdl_file := SFDL_Files[0]
				if DEBUG {
					fmt.Println("sfdl_file:", sfdl_file)
				}
				go startLoaderFunctions(sfdl_file)
			}
		}()
	})
	http.Handle("/", s.setServerHeaders(mux))

	// add rate limit for more security
	// limiter := rate.NewLimiter(rate.Every(time.Second/5), 5)
	limiter := rate.NewLimiter(WWWRateLimit, WWWRateLimit_Times)
	handler := s.setServerHeaders(rateLimiter(limiter, mux))

	ipAddresses, err := GetIPAddresses()
	if err != nil {
		log.Fatal(err)
	}

	if s.UseTLS {
		if WWWServerIP == "" || WWWServerIP == "0.0.0.0" && WWWServerIP != "127.0.0.1" && WWWServerIP != "::1" {
			for _, url := range ipAddresses {
				fmt.Printf("Webserver starting @ https://%s:%d/\n", url, WWWServerPort)
			}
		} else {
			fmt.Printf("Webserver starting @ https://%s:%d/\n", WWWServerIP, WWWServerPort)
		}
		go func() {
			if err := http.ListenAndServeTLS(s.Addr, filepath.Join(UserHomeDir, s.TLSCert), filepath.Join(UserHomeDir, s.TLSKey), handler); err != nil {
				log.Printf("error starting https webserver: %v", err)
			}
			s.quitCh <- true
		}()
		<-s.quitCh
	} else {
		if WWWServerIP == "" || WWWServerIP == "0.0.0.0" && WWWServerIP != "127.0.0.1" && WWWServerIP != "::1" {
			for _, url := range ipAddresses {
				fmt.Printf("Webserver starting @ http://%s:%d/\n", url, WWWServerPort)
			}
		} else {
			fmt.Printf("Webserver starting @ http://%s:%d/\n", WWWServerIP, WWWServerPort)
		}
		go func() {
			if err := http.ListenAndServe(s.Addr, handler); err != nil {
				log.Printf("error starting webserver: %v", err)
			}
			s.quitCh <- true
		}()
		<-s.quitCh
	}
}

func (s *Server) setServerHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		os := runtime.GOOS
		w.Header().Set("Server", fmt.Sprintf("goSFDLSauger/%s (%s)", VERSION, os))
		w.Header().Set("Access-Control-Allow-Origin", "*")
		next.ServeHTTP(w, r)
	})
}

func rateLimiter(limiter *rate.Limiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			sendServerResponseJson("error", "rate limit exceeded", w, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func IsUserLoggedIn(w http.ResponseWriter, r *http.Request, bypass bool) bool {
	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value == "" {
		if !bypass {
			sendServerResponseJson("error", "unauthorized", w, http.StatusUnauthorized)
		}
		return false
	}
	sessionData, exists := sessions[cookie.Value]
	if !exists || !sessionData.IsLoggedIn {
		if !bypass {
			sendServerResponseJson("error", "unauthorized", w, http.StatusUnauthorized)
		}
		return false
	}
	return true
}

func sendServerResponseJson(status, message string, w http.ResponseWriter, statusCode int) {
	response := ServerResponse{
		Status:  status,
		Message: message,
	}
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "error sending json encoded response", http.StatusInternalServerError)
		return
	}
}

func contentHandler(w http.ResponseWriter, r *http.Request) {
	if !IsUserLoggedIn(w, r, true) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value == "" {
		sendServerResponseJson("error", "unauthorized", w, http.StatusUnauthorized)
		return
	}

	sessionData, exists := sessions[cookie.Value]
	if !exists || !sessionData.IsLoggedIn {
		sendServerResponseJson("error", "unauthorized", w, http.StatusUnauthorized)
		return
	}

	contentFS, err := fs.Sub(content, "www")
	if err != nil {
		sendServerResponseJson("error", "error unable to read content", w, http.StatusInternalServerError)
		return
	}

	if r.URL.Path == "/" {
		file, err := contentFS.Open("index.html")
		if err != nil {
			sendServerResponseJson("error", "error opening index.html", w, http.StatusInternalServerError)
			return
		}
		defer file.Close()

		data, err := io.ReadAll(file)
		if err != nil {
			sendServerResponseJson("error", "error reading index.html", w, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html")

		tmpl, err := template.New("index").Parse(string(makeTemplate(data)))
		if err != nil {
			sendServerResponseJson("error", "error loading template", w, http.StatusInternalServerError)
			return
		}

		tmpl.Execute(w, map[string]interface{}{
			"CSRFToken": sessionData.CSRFToken,
			"VERSION":   VERSION,
		})

		return
	}

	filePath := r.URL.Path[1:]

	fileNameWithExt := filepath.Base(filePath)
	fileName := strings.TrimSuffix(fileNameWithExt, filepath.Ext(fileNameWithExt))

	file, err := contentFS.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			sendServerResponseJson("error", "404 - page not found", w, http.StatusNotFound)
			return
		}
		sendServerResponseJson("error", "error opening the file", w, http.StatusInternalServerError)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		sendServerResponseJson("error", "error reading file", w, http.StatusInternalServerError)
		return
	}

	if strings.HasSuffix(filePath, ".html") ||
		strings.HasSuffix(filePath, ".htm") ||
		strings.HasSuffix(filePath, ".tpl") {
		w.Header().Set("Content-Type", "text/html")

		tmpl, err := template.New(fileName).Parse(string(makeTemplate(data)))
		if err != nil {
			sendServerResponseJson("error", "error loading template", w, http.StatusInternalServerError)
			return
		}

		tmpl.Execute(w, map[string]interface{}{
			"CSRFToken": sessionData.CSRFToken,
			"VERSION":   VERSION,
		})
	} else {
		w.Header().Set("Content-Type", getContentType(filePath))
		w.Write(data)
	}
}

func makeTemplate(data []byte) []byte {
	re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	matches := re.FindSubmatch(data)
	if len(matches) > 1 {
		originalTitle := string(matches[1])
		newTitle := fmt.Sprintf("%s - goSFDLSauger v%s", originalTitle, VERSION)
		return re.ReplaceAll(data, []byte("<title>"+newTitle+"</title>"))
	}
	reHead := regexp.MustCompile(`(?i)</head>`)
	dataWithTitle := reHead.ReplaceAll(data, []byte(fmt.Sprintf("<title>goSFDLSauger v%s</title></head>", VERSION)))
	return dataWithTitle
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		password := r.FormValue("password")
		if hashPassword(password) == loginData {
			sessionID, err := generateSessionID()
			if err != nil {
				sendServerResponseJson("error", "error login session", w, http.StatusInternalServerError)
				return
			}

			randomCSRFKey, keyErr := generateRandomPassword(32)
			if keyErr != nil {
				sendServerResponseJson("error", "error unable to generate randomCSRFKey", w, http.StatusInternalServerError)
				return
			}

			hash := sha256.New()
			hash.Write([]byte(randomCSRFKey))
			randomCSRFKey = hex.EncodeToString(hash.Sum(nil))

			sessions[sessionID] = Session{
				IsLoggedIn: true,
				CSRFToken:  randomCSRFKey,
			}

			http.SetCookie(w, &http.Cookie{
				Name:     "session",
				Value:    sessionID,
				Path:     "/",
				Secure:   true,
				SameSite: http.SameSiteNoneMode, // http.SameSiteStrictMode
			})

			http.Redirect(w, r, "/index.html", http.StatusSeeOther)
			return
		}
		sendServerResponseJson("error", "wrong password", w, http.StatusUnauthorized)
		return
	}

	fs, err := content.ReadFile("www/login.html")
	if err != nil {
		sendServerResponseJson("error", "error loading template", w, http.StatusInternalServerError)
		return
	}

	tmpl, err := template.New("login").Parse(string(makeTemplate(fs)))
	if err != nil {
		sendServerResponseJson("error", "error loading template", w, http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, map[string]interface{}{
		"VERSION": VERSION,
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		delete(sessions, cookie.Value)
		http.SetCookie(w, &http.Cookie{
			Name:   "session",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func eventsHandler(w http.ResponseWriter, r *http.Request) {
	if !IsUserLoggedIn(w, r, false) {
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		sendServerResponseJson("error", "streaming not supported!", w, http.StatusInternalServerError)
		return
	}

	for {
		// server info
		for _, downloadProgress := range ProgressGlobals {
			server, err := json.Marshal(downloadProgress)
			if err != nil {
				sendServerResponseJson("error", "failed to encode server data", w, http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, "data: {\"server\": %s}\n\n", server)
			flusher.Flush()
		}

		// files info
		for _, progress := range ProgessFiles {
			files, err := json.Marshal(progress)
			if err != nil {
				sendServerResponseJson("error", "failed to encode files data", w, http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, "data: {\"files\": %s}\n\n", files)
			flusher.Flush()
		}

		// logs
		for _, log := range DownloadLogs {
			logs, err := json.Marshal(log)
			if err != nil {
				sendServerResponseJson("error", "failed to encode logs data", w, http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, "data: {\"logs\": %s}\n\n", logs)
			flusher.Flush()
		}

		time.Sleep(1 * time.Second)
	}
}

func logsHandler(w http.ResponseWriter, r *http.Request) {
	if !IsUserLoggedIn(w, r, false) {
		return
	}

	for _, log := range LoaderLogs {
		logs, err := json.Marshal(log)
		if err != nil {
			sendServerResponseJson("error", "failed to encode logs data", w, http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "data: {\"logs\": %s}\n\n", logs)
	}
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	if !IsUserLoggedIn(w, r, false) {
		return
	}

	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value == "" {
		sendServerResponseJson("error", "unauthorized", w, http.StatusUnauthorized)
		return
	}

	sessionData, exists := sessions[cookie.Value]
	if !exists || !sessionData.IsLoggedIn {
		sendServerResponseJson("error", "unauthorized", w, http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodPost {
		oldPassword := r.FormValue("oldPASS")
		newPassword := r.FormValue("newPASS")
		confirmPassword := r.FormValue("conPASS")

		csrfToken := r.Header.Get("X-CSRF-Token")
		if csrfToken != sessionData.CSRFToken {
			sendServerResponseJson("error", "unauthorized", w, http.StatusUnauthorized)
			return
		}

		if oldPassword == newPassword {
			sendServerResponseJson("error", "old and new password is the same", w, http.StatusBadRequest)
			return
		}

		if newPassword != confirmPassword {
			sendServerResponseJson("error", "new passwords do not match", w, http.StatusBadRequest)
			return
		}

		if hashPassword(oldPassword) != loginData {
			sendServerResponseJson("error", "old password is incorrect", w, http.StatusBadRequest)
			return
		}

		err := setNewPassword(newPassword)
		if err != nil {
			sendServerResponseJson("error", "Set new password error: "+err.Error(), w, http.StatusInternalServerError)
		}

		loginData = hashPassword(newPassword)

		sendServerResponseJson("success", "password successfully changed!", w, http.StatusOK)
	} else {
		sendServerResponseJson("error", "invalid request method", w, http.StatusBadRequest)
	}
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if !IsUserLoggedIn(w, r, false) {
		return
	}

	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value == "" {
		sendServerResponseJson("error", "unauthorized", w, http.StatusUnauthorized)
		return
	}

	sessionData, exists := sessions[cookie.Value]
	if !exists || !sessionData.IsLoggedIn {
		sendServerResponseJson("error", "unauthorized", w, http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		sendServerResponseJson("error", "invalid request method", w, http.StatusBadRequest)
		return
	}

	csrfToken := r.Header.Get("X-CSRF-Token")
	if csrfToken != sessionData.CSRFToken {
		sendServerResponseJson("error", "unauthorized", w, http.StatusUnauthorized)
		return
	}

	err = r.ParseMultipartForm(10 << 20) // max 10 MB
	if err != nil {
		sendServerResponseJson("error", "error parsing upload form", w, http.StatusBadRequest)
		return
	}

	files := r.MultipartForm.File["fileInput"]
	for _, fileHeader := range files {
		file, err := fileHeader.Open()
		if err != nil {
			sendServerResponseJson("error", "error opening file", w, http.StatusInternalServerError)
			return
		}
		defer file.Close()

		if err := os.MkdirAll(filepath.Join(UserDownloadDir, "/sfdl_files"), os.ModePerm); err != nil {
			sendServerResponseJson("error", "error creating directory for sfdl files", w, http.StatusInternalServerError)
			return
		}

		dst, err := os.Create(filepath.Join(UserDownloadDir, "/sfdl_files") + "/" + fileHeader.Filename)
		if err != nil {
			sendServerResponseJson("error", "error creating sfdl file", w, http.StatusInternalServerError)
			return
		}
		defer dst.Close()

		if _, err := io.Copy(dst, file); err != nil {
			sendServerResponseJson("error", "error saving sfdl data", w, http.StatusInternalServerError)
			return
		}

		SFDL_Files = append(SFDL_Files, dst.Name())
	}

	responseMessage := map[string]string{"message": "SFDL file(s) uploaded successfully!"}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(responseMessage)

	go func() {
		if len(SFDL_Files) > 0 {
			sfdl_file := SFDL_Files[0]
			startLoaderFunctions(sfdl_file)
		}
	}()
}

func fileHandler(w http.ResponseWriter, r *http.Request) {
	if !IsUserLoggedIn(w, r, false) {
		return
	}

	baseDir := DestinationDownloadPath

	pathVar := r.URL.Query().Get("path")
	relativePath := strings.TrimPrefix(pathVar, "/files?path=")

	dlVar := r.URL.Query().Get("dl")
	webDlFile := strings.TrimPrefix(dlVar, "/files?dl=")

	csrfVar := r.URL.Query().Get("csrf")
	csrfString := strings.TrimPrefix(csrfVar, "&csrf=")

	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value == "" {
		sendServerResponseJson("error", "unauthorized", w, http.StatusUnauthorized)
		return
	}

	sessionData, exists := sessions[cookie.Value]
	if !exists || !sessionData.IsLoggedIn {
		sendServerResponseJson("error", "unauthorized", w, http.StatusUnauthorized)
		return
	}

	// download file
	if webDlFile != "" {
		if sessionData.CSRFToken != csrfString {
			sendServerResponseJson("error", "unauthorized", w, http.StatusUnauthorized)
			return
		}
		filePath := filepath.Join(baseDir, webDlFile)
		downloadHandler(w, r, filePath, filepath.Base(webDlFile))
	}

	if relativePath != "" && sessionData.CSRFToken != csrfString {
		sendServerResponseJson("error", "unauthorized", w, http.StatusUnauthorized)
		return
	}

	files, err := listFiles(baseDir, relativePath)
	if err != nil {
		sendServerResponseJson("error", "error reading (relativePath): "+relativePath, w, http.StatusInternalServerError)
		return
	}

	var fileList []File
	for _, f := range files {
		fileList = append(fileList, File{
			Name:  f.Name,
			IsDir: f.IsDir,
			Path:  relativePath + "/" + f.Name,
			Size:  FormatBytes(uint64(getFileSize(RemoveDuplicateSlashes(baseDir + "/" + relativePath + "/" + f.Name)))),
		})
	}

	tmplContent, err := content.ReadFile("www/filetree.html")
	if err != nil {
		sendServerResponseJson("error", "error reading template", w, http.StatusInternalServerError)
		return
	}

	tmpl, err := template.New("filetree").Parse(string(makeTemplate(tmplContent)))
	if err != nil {
		sendServerResponseJson("error", fmt.Sprintf("error creating template: %v", err), w, http.StatusInternalServerError)
		return
	}

	pathParts := strings.Split(RemoveDuplicateSlashes(relativePath), "/")

	// remove empty bread crumbs
	var filteredPathParts []string
	for _, part := range pathParts {
		if part != "" {
			filteredPathParts = append(filteredPathParts, part)
		}
	}

	data := struct {
		Files     []File
		Path      string
		PathParts []string
		CSRFToken string
		VERSION   string
	}{
		Files:     fileList,
		Path:      relativePath,
		PathParts: filteredPathParts,
		CSRFToken: sessionData.CSRFToken,
		VERSION:   VERSION,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		sendServerResponseJson("error", "error rendering template", w, http.StatusInternalServerError)
		return
	}
}

func deleteFileOrDir(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}

		for _, entry := range entries {
			err := deleteFileOrDir(filepath.Join(path, entry.Name()))
			if err != nil {
				return err
			}
		}

		return os.Remove(path)
	}

	return os.Remove(path)
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	if !IsUserLoggedIn(w, r, false) {
		return
	}

	csrfVar := r.URL.Query().Get("csrf")
	csrfString := strings.TrimPrefix(csrfVar, "&csrf=")

	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value == "" {
		sendServerResponseJson("error", "unauthorized", w, http.StatusUnauthorized)
		return
	}

	sessionData, exists := sessions[cookie.Value]
	if !exists || !sessionData.IsLoggedIn {
		sendServerResponseJson("error", "unauthorized", w, http.StatusUnauthorized)
		return
	}

	if csrfString != sessionData.CSRFToken {
		sendServerResponseJson("error", "unauthorized", w, http.StatusUnauthorized)
		return
	}

	path := r.URL.Query().Get("path")
	path = DestinationDownloadPath + path

	if path == "" {
		sendServerResponseJson("error", "a valid path is required", w, http.StatusBadRequest)
		return
	}

	err = deleteFileOrDir(path)
	if err != nil {
		sendServerResponseJson("error", fmt.Sprintf("Error deleting file: %v", err), w, http.StatusInternalServerError)
		return
	}

	sendServerResponseJson("success", fmt.Sprintf("%s deleted successfully!", path), w, http.StatusOK)
}

func sendMQTTHandler(w http.ResponseWriter, r *http.Request) {
	if !IsUserLoggedIn(w, r, false) {
		return
	}

	if !UseMQTT {
		sendServerResponseJson("error", "MQTT not available, no broker was set!", w, http.StatusInternalServerError)
		return
	}

	message := r.URL.Query().Get("mqttmsg")

	if message == "" {
		sendServerResponseJson("error", "a massage (empty) is required", w, http.StatusBadRequest)
		return
	}

	msgerr := SendMQTTMsg(message)
	if msgerr != nil {
		sendServerResponseJson("error", "error sending MQTT message: "+message+" | "+fmt.Sprintf("error: %s", msgerr), w, http.StatusInternalServerError)
		return
	}

	sendServerResponseJson("success", "MQTT broker got your message: "+message, w, http.StatusOK)
}

func downloadHandler(w http.ResponseWriter, r *http.Request, filePath, fileName string) {
	if !IsUserLoggedIn(w, r, false) {
		return
	}

	file, err := os.Open(RemoveDuplicateSlashes(filePath))
	if err != nil {
		http.Error(w, "unable to open file for download (webserver)", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", getFileSize(filePath)))

	http.ServeContent(w, r, fileName, getFileModTime(filePath), file)
}

func getFileSize(filePath string) int64 {
	info, err := os.Stat(filePath)
	if err != nil {
		return 0
	}
	return info.Size()
}

func getFileModTime(filePath string) time.Time {
	info, err := os.Stat(filePath)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

func listFiles(baseDir, relativePath string) ([]File, error) {
	var fileList []File

	path := RemoveDuplicateSlashes(baseDir + "/" + relativePath)

	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	files, err := dir.ReadDir(0)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		fileList = append(fileList, File{
			Name:  file.Name(),
			IsDir: file.IsDir(),
			Path:  RemoveDuplicateSlashes("/files?path=" + relativePath + "/" + file.Name()),
		})
	}

	return fileList, nil
}

func NewCertManager(certFile, keyFile string) *CertManager {
	return &CertManager{
		CertFile: certFile,
		KeyFile:  keyFile,
	}
}

func (cm *CertManager) GenerateSelfSignedCert() error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("error creating key: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("error creating serial: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"GrafSauger"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("error creating cert: %v", err)
	}

	certOut, err := os.Create(cm.CertFile)
	if err != nil {
		return fmt.Errorf("error unable to open cert: %v", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("error unable to write new cert file: %v", err)
	}

	keyOut, err := os.Create(cm.KeyFile)
	if err != nil {
		return fmt.Errorf("error unable to open key file: %v", err)
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("error unable to marshal key: %v", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("error unable to write key: %v", err)
	}

	if UseConfig {
		config.WebServer.SSLCertPath = cm.CertFile
		config.WebServer.SSLKeyPath = cm.KeyFile
		err := saveConfig(CONFIG_File)
		if err != nil {
			fmt.Println("error saving config file while updating cert and key files:", err)
		}
	}

	fmt.Printf("New %s created!\n", cm.CertFile)
	fmt.Printf("New %s created!\n", cm.KeyFile)
	return nil
}

func GetIPAddresses() ([]string, error) {
	var ipAddresses []string

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("error reading network interfaces: %v", err)
	}

	for _, i := range interfaces {
		addrs, err := i.Addrs()
		if err != nil {
			log.Println("error unable to get network addresses:", err)
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip.To4() != nil {
				ipAddresses = append(ipAddresses, ip.String())
			} else if ip.To16() != nil {
				ipAddresses = append(ipAddresses, fmt.Sprintf("[%s]", ip.String()))
			}
		}
	}

	return ipAddresses, nil
}

func hashPassword(password string) string {
	first := "u9RAXwJGytMZjzTsCq4vHK"
	second := "JrKMdhwCN584P7pLSnvuH2"
	if len(superSalt) >= 5 {
		first = first + superSalt[:5]
		second = superSalt[:5] + second
	}
	password = superSalt + first + password + second
	hash1 := sha256.New()
	hash1.Write([]byte(password))
	sum := hex.EncodeToString(hash1.Sum(nil))
	password = "Sauger" + second + sum + first + password + "Graf" + superSalt
	hash2 := sha256.New()
	hash2.Write([]byte(password))
	return hex.EncodeToString(hash2.Sum(nil))
}

func passwordExists() bool {
	_, err := os.Stat(filepath.Join(UserHomeDir, passwordFile))
	return !os.IsNotExist(err)
}

func savePassword(hashedPassword string) error {
	if err := os.MkdirAll(UserHomeDir, 0755); err != nil {
		return fmt.Errorf("error creating directory: %w", err)
	}
	fmt.Println("new password file created:", filepath.Join(UserHomeDir, passwordFile))
	return os.WriteFile(filepath.Join(UserHomeDir, passwordFile), []byte(hashedPassword), 0644)
}

func generateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	var password []byte

	rng := mathRand.New(mathRand.NewSource(time.Now().UnixNano()))

	for i := 0; i < length; i++ {
		randomIndex := rng.Intn(len(charset))
		password = append(password, charset[randomIndex])
	}

	return string(password), nil
}

func generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func setNewPassword(password string) error {
	hashedPassword := hashPassword(password)
	err := savePassword(hashedPassword)
	if err != nil {
		fmt.Println("error saving webgui password:", err)
		return err
	}
	return nil
}

func GoWebserver(serverPORT int, serverIP string) {
	// get the users home directory
	confDir, err := os.UserConfigDir()
	if err != nil {
		fmt.Println("error getting users default-config directory:", err)
		return
	} else {
		UserHomeDir = confDir
	}

	if UserHomeDir != "." {
		UserHomeDir = filepath.Join(UserHomeDir, "/goSFDLSauger")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("error getting users default-home directory:", err)
		return
	}

	if UserDownloadDir == "" {
		UserDownloadDir = filepath.Join(homeDir, "/Downloads")
		_, err := os.Stat(UserDownloadDir)
		if os.IsNotExist(err) {
			UserDownloadDir = ""
			fmt.Println("error users default download directory does not exist:", err)
		}
	}

	// check if we got a password(file)
	if !passwordExists() {
		password, err := generateRandomPassword(passwordLength)
		if err != nil {
			fmt.Println("error generating password:", err)
			return
		}
		hashedPassword := hashPassword(password)
		err = savePassword(hashedPassword)
		if err != nil {
			fmt.Println("error saving password:", err)
			return
		}
		fmt.Println("[!] your new random webgui password:", password)
	}

	// load password file
	data, err := os.ReadFile(filepath.Join(UserHomeDir, passwordFile))
	if err != nil {
		fmt.Println("error reading login data from file:", filepath.Join(UserHomeDir, passwordFile))
		return
	} else {
		loginData = string(data)
	}

	// set server ip, port and start the server
	if serverPORT > 0 {
		WWWServerPort = serverPORT
	}
	if serverIP != "" {
		WWWServerIP = serverIP
		server := NewServer(WWWServerIP+":"+strconv.Itoa(WWWServerPort), "server.crt", "server.key")
		server.Start()
	} else {
		server := NewServer(":"+strconv.Itoa(WWWServerPort), "server.crt", "server.key")
		server.Start()
	}
}
