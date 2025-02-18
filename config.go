package main

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
)

type FormField struct {
	ID        string      `json:"id"`
	Label     string      `json:"label"`
	Type      string      `json:"type"`
	Value     interface{} `json:"value"`
	Category  string      `json:"category,omitempty"`
	Subfields []FormField `json:"subfields,omitempty"`
}

type GoSFDLSaugerConfig struct {
	Debug        bool   `yaml:"debug"`
	SFDLPassword string `yaml:"sfdl_password"`
	SFDLInput    string `yaml:"sfdl_input"`
	Destination  string `yaml:"destinationDownload"`
	MaxThreads   int    `yaml:"max_threads"`
	UseUnrar     bool   `yaml:"use_unrar"`
	FTPTimeout   int    `yaml:"ftp_timeout"`
}

type WebServerConfig struct {
	UseWebserver bool   `yaml:"use"`
	WWWHost      string `yaml:"host"`
	WWWPort      int    `yaml:"port"`
	WWWLogin     string `yaml:"login"`
	UseSSL       bool   `yaml:"ssl"`
	SSLCertPath  string `yaml:"ssl_cert_path"`
	SSLKeyPath   string `yaml:"ssl_key_path"`
}

type Socks5Config struct {
	UseSocks5 bool   `yaml:"use"`
	SocksHost string `yaml:"host"`
	SocksPort int    `yaml:"port"`
	SocksUser string `yaml:"user"`
	SocksPass string `yaml:"pass"`
}

type MqttConfig struct {
	UseMqtt  bool   `yaml:"use"`
	Broker   string `yaml:"broker"`
	Topic    string `yaml:"topic"`
	MqttUser string `yaml:"user"`
	MqttPass string `yaml:"pass"`
}

type Config struct {
	GoSFDLSauger GoSFDLSaugerConfig `yaml:"goSFDLSauger"`
	WebServer    WebServerConfig    `yaml:"webserver"`
	Socks5       Socks5Config       `yaml:"socks5"`
	Mqtt         MqttConfig         `yaml:"mqtt"`
}

var config Config

func loadConfig(configFile string) error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, &config)
}

func saveConfig(configFile string) error {
	data, err := yaml.Marshal(&config)
	if err != nil {
		return err
	}
	return os.WriteFile(configFile, data, 0644)
}

func createDefaultConfig(configFile string) error {
	// main config
	config.GoSFDLSauger.Debug = false
	config.GoSFDLSauger.SFDLPassword = "mlcboard.com"

	// get users home dir
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}

	// set path to look for sfdl files
	config.GoSFDLSauger.SFDLInput = filepath.Join(homeDir, "/Downloads/sfdl_files")

	// set download path
	destPath := filepath.Join(homeDir, "/Downloads")
	_, err = os.Stat(destPath)
	if os.IsNotExist(err) {
		destPath = ""
	}
	config.GoSFDLSauger.Destination = destPath
	config.GoSFDLSauger.MaxThreads = 3
	config.GoSFDLSauger.UseUnrar = true
	config.GoSFDLSauger.FTPTimeout = 30

	// WebGUI
	config.WebServer.UseWebserver = false
	config.WebServer.WWWHost = "0.0.0.0"
	config.WebServer.WWWPort = 8080
	config.WebServer.WWWLogin = ""
	config.WebServer.UseSSL = true
	config.WebServer.SSLCertPath = ""
	config.WebServer.SSLKeyPath = ""

	// socks5
	config.Socks5.UseSocks5 = false
	config.Socks5.SocksHost = "127.0.0.1"
	config.Socks5.SocksPort = 9090
	config.Socks5.SocksUser = ""
	config.Socks5.SocksPass = ""

	// mqtt
	config.Mqtt.UseMqtt = false
	config.Mqtt.Broker = ""
	config.Mqtt.Topic = "goSFDLSauger"
	config.Mqtt.MqttUser = ""
	config.Mqtt.MqttPass = ""

	// save default config file
	if err := saveConfig(configFile); err != nil {
		fmt.Println("error saving default config file:" + err.Error())
		return err
	}

	return nil
}

func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil
}

func addFieldToCategory(fields *[]FormField, field FormField) {
	if field.Type == "" && field.Value == nil {
		*fields = append(*fields, field)
	} else {
		categoryName := strings.Split(field.ID, "_")[0]
		for i := range *fields {
			if (*fields)[i].Label == categoryName {
				(*fields)[i].Subfields = append((*fields)[i].Subfields, field)
				return
			}
		}
		*fields = append(*fields, FormField{
			ID:        categoryName,
			Label:     categoryName,
			Type:      "category",
			Value:     nil,
			Subfields: []FormField{field},
		})
	}
}

func generateFormFields(config interface{}, prefix string, fields *[]FormField) {
	val := reflect.ValueOf(config)
	typ := reflect.TypeOf(config)

	if val.Kind() == reflect.Struct {
		for i := 0; i < val.NumField(); i++ {
			fieldVal := val.Field(i)
			fieldType := typ.Field(i)

			if fieldType.PkgPath != "" {
				continue
			}

			fieldID := prefix + fieldType.Name
			fieldID = strings.ReplaceAll(fieldID, ".", "_")

			fieldLabel := fieldType.Name

			var fieldTypeString string
			var fieldValue interface{}

			switch fieldVal.Kind() {
			case reflect.Bool:
				fieldTypeString = "checkbox"
				fieldValue = fmt.Sprintf("%v", fieldVal.Bool())
			case reflect.String:
				fieldTypeString = "text"
				fieldValue = fieldVal.String()
			case reflect.Int:
				fieldTypeString = "number"
				fieldValue = fmt.Sprintf("%d", fieldVal.Int())
			case reflect.Struct:
				generateFormFields(fieldVal.Interface(), fieldID+".", fields)
				continue
			default:
				continue
			}

			field := FormField{
				ID:    fieldID,
				Label: fieldLabel,
				Type:  fieldTypeString,
				Value: fieldValue,
			}

			addFieldToCategory(fields, field)
		}
	}
}

func configHandler(w http.ResponseWriter, r *http.Request) {
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

	if err := loadConfig(CONFIG_File); err != nil {
		confDir, err := os.UserConfigDir()
		if err == nil {
			defaultCPath := filepath.Join(confDir, "/goSFDLSauger/config.yaml")
			err = createDefaultConfig(defaultCPath)
			if err != nil {
				sendServerResponseJson("error", "error creating default config file: "+err.Error(), w, http.StatusInternalServerError)
			} else {
				CONFIG_File = defaultCPath
			}
		} else {
			sendServerResponseJson("error", "error loading config file: "+err.Error(), w, http.StatusInternalServerError)
			return
		}
	}

	var fields []FormField
	generateFormFields(config, "", &fields)

	tmplContent, err := content.ReadFile("www/config.html")
	if err != nil {
		sendServerResponseJson("error", "error loading template", w, http.StatusInternalServerError)
		return
	}

	tmpl, err := template.New("config").Parse(string(makeTemplate(tmplContent)))
	if err != nil {
		sendServerResponseJson("error", "error creating template", w, http.StatusInternalServerError)
		return
	}

	data := struct {
		Fields    []FormField
		CSRFToken string
		VERSION   string
	}{
		Fields:    fields,
		CSRFToken: sessionData.CSRFToken,
		VERSION:   VERSION,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		sendServerResponseJson("error", "error rendering template", w, http.StatusInternalServerError)
	}
}

func configUpdateHandler(w http.ResponseWriter, r *http.Request) {
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
		err := r.ParseForm()
		if err != nil {
			sendServerResponseJson("error", "error parsing form", w, http.StatusInternalServerError)
			return
		}

		if sessionData.CSRFToken != r.FormValue("_csrf") {
			sendServerResponseJson("error", "unauthorized", w, http.StatusUnauthorized)
			return
		}

		formDataWithDefaults := getFormDataWithDefaults(r)

		for key, values := range formDataWithDefaults {
			for _, value := range values {
				if key != "_csrf" { // ignor CSRF
					updateConfig(&config, key, value)
				}
			}
		}

		if err := saveConfig(CONFIG_File); err != nil {
			sendServerResponseJson("error", "error saving config file", w, http.StatusInternalServerError)
			return
		}

		sendServerResponseJson("success", "config successfully updated!", w, http.StatusOK)
	}
}

// all this tango because form data
// does not contain unchecked checkboxes at all
func getFormDataWithDefaults(r *http.Request) map[string][]string {
	// get form data
	formData := make(map[string][]string)
	for key, values := range r.Form {
		formData[key] = values
	}

	// get all boolean config entries aka checkboxes
	val := reflect.ValueOf(config)
	typ := reflect.TypeOf(config)
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldName := typ.Field(i).Name
		if field.Kind() == reflect.Struct {
			for j := 0; j < field.NumField(); j++ {
				subField := field.Field(j)
				subFieldName := typ.Field(i).Type.Field(j).Name
				// if config entry is boolean, it is a checkbox in web forms
				if subField.Kind() == reflect.Bool {
					searchForName := fieldName + "_" + subFieldName + "_checkbox"
					// if config entry is missing in form data, we add it as false
					if _, exists := formData[searchForName]; !exists {
						formData[searchForName] = []string{"false"}
					}
				}
			}
		}
	}

	// now we clean up form data checkbox entries and remove _checkbox
	for key, value := range formData {
		if len(key) > 8 && key[len(key)-9:] == "_checkbox" {
			newKey := key[:len(key)-9]
			formData[newKey] = []string{fmt.Sprintf("%v", value)}
			delete(formData, key)
		}
	}

	return formData
}

func updateConfig(config interface{}, key, value string) {
	parts := strings.Split(key, "_")
	if len(parts) < 2 {
		fmt.Println("updateConfig: invalid key format, returning")
		return
	}

	category := parts[0]
	field := strings.Join(parts[1:], "_")
	keyPath := category + "." + field

	val := reflect.ValueOf(config)
	if val.Kind() != reflect.Ptr {
		fmt.Println("updateConfig: config is not a pointer, returning")
		return
	}

	val = val.Elem()
	parts = strings.Split(keyPath, ".")

	for i, part := range parts {
		if i == len(parts)-1 {
			field := val.FieldByName(part)
			if field.IsValid() {
				switch field.Kind() {
				case reflect.Bool:
					boolValue := false
					value = strings.Trim(value, "[]")
					if value == "on" || value == "true" {
						boolValue = true
					}
					field.SetBool(boolValue)
				case reflect.Int:
					intValue, err := strconv.Atoi(value)
					if err == nil {
						field.SetInt(int64(intValue))
					}
				case reflect.String:
					field.SetString(value)
				case reflect.Slice:
					if field.Type().Elem().Kind() == reflect.Struct {
						handleSubfields(field, value)
					}
				case reflect.Interface:
					handleComplexValue(field, value)
				}
			} else {
				fmt.Printf("updateConfig: field %s not found in config\n", part)
			}
		} else {
			val = val.FieldByName(part)
			if !val.IsValid() {
				fmt.Printf("updateConfig: field %s not found in config\n", part)
				return
			}
		}
	}
}

func handleSubfields(field reflect.Value, value string) {
	if field.Kind() == reflect.Slice {
		for i := 0; i < field.Len(); i++ {
			subField := field.Index(i)
			handleComplexValue(subField, value)
		}
	}
}

func handleComplexValue(field reflect.Value, value string) {
	switch field.Type().Name() {
	case "FormField":
		valueField := field.FieldByName("Value")
		if valueField.IsValid() {
			switch valueField.Kind() {
			case reflect.String:
				valueField.SetString(value)
			case reflect.Int:
				if intValue, err := strconv.Atoi(value); err == nil {
					valueField.SetInt(int64(intValue))
				}
			case reflect.Bool:
				boolValue := value == "true" || value == "on" || value == "1"
				valueField.SetBool(boolValue)
			}
		}
	}
}
