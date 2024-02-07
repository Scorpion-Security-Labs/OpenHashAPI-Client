// Package models contains structs and functions for validating objects
package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
)

// The Configuration struct is used to load configuration files
type Configuration struct {
	ServerURL      string `json:"server-url"`
	ServerPort     string `json:"server-port"`
	ServerAPIRoute string `json:"server-api-route"`
	ClientUsername string `json:"client-username"`
	ClientPassword string `json:"client-password"`
}

// The UserCredentials struct is used for authentication
type UserCredentials struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// The UploadHashes struct is used to upload new hashes
type UploadHashes struct {
	Algorithm string   `json:"algorithm"`
	HashPlain []string `json:"hash-plain"`
}

// The SearchHashes struct is used to search for hashes
type SearchHashes struct {
	Data []string `json:"data"`
}

// The UserPermissions struct is used to update user permissions
type UserPermissions struct {
	UserID    int  `json:"userID"`
	CanLogin  bool `json:"canLogin"`
	CanSearch bool `json:"canSearch"`
	CanUpload bool `json:"canUpload"`
	CanManage bool `json:"canManage"`
}

// IsStringInt validates if a string is an integer
func IsStringInt(str string) bool {
	IsInt := regexp.MustCompile(`^[0-9]+$`).MatchString
	if IsInt(str) == false {
		return false
	}
	return true
}

// IsStringValidFileName validates if a string only contains expected
// characters
func IsStringValidFileName(str string) bool {
	IsValidFileName := regexp.MustCompile(`^[a-zA-Z0-9_\.\-/]+$`).MatchString
	if IsValidFileName(str) == false {
		return false
	}
	return true
}

// ValidateIntInputArgs validates arguments provided for a valid hash algorithm
func ValidateIntInputArgs(args []string, index int) (string, error) {
	if len(args) < index {
		return "", errors.New("Invalid Number Input")
	}
	if IsStringInt(args[index]) == false {
		return "", fmt.Errorf("Invalid Number Input: %s", args[index])
	}

	return args[index], nil
}

// ValidateQueryStringArgs validate arguments provided for the query string
func ValidateQueryStringArgs(args []string, index int) (string, error) {
	if len(args)-1 < index {
		return "", nil
	}

	if !regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*()_+=.-]*$`).MatchString(args[index]) {
		return "", errors.New("Query string contains invalid characters")
	}

	return args[index], nil
}

// ValidateFileInputArgs validate arguments provided for a valid file
func ValidateFileInputArgs(args []string, index int) (string, error) {
	if len(args) < index {
		return "", errors.New("file argument not found")
	}

	_, err := os.Stat(args[index])
	if err != nil {
		return "", err
	}

	if IsStringValidFileName(args[index]) == false {
		return "", errors.New("Filename contained invalid characters")
	}

	return args[index], nil
}

// ValidateConfig validates the config from ENV vars
func ValidateConfig(config Configuration) error {
	// Validate the server URL
	serverURL := fmt.Sprintf("https://%s:%s%s", config.ServerURL, config.ServerPort, config.ServerAPIRoute)
	if !regexp.MustCompile(`^https?:\/\/[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+`).MatchString(serverURL) {
		return fmt.Errorf("invalid server URL")
	}
	// Validate the server port
	if !regexp.MustCompile(`^[0-9]+`).MatchString(config.ServerPort) {
		return fmt.Errorf("invalid server port")
	}
	// Validate the username
	if len(config.ClientUsername) < 3 || !regexp.MustCompile(`^[a-zA-Z0-9]`).MatchString(config.ClientUsername) {
		return fmt.Errorf("Invalid username. Expected at least 3 alphanumeric characters. Got: %s", config.ClientUsername)
	}
	// Validate the password
	if len(config.ClientPassword) < 12 {
		fmt.Println(config)
		return fmt.Errorf("passwords must be at least 12 characters long and contain a mix of uppercase, lowercase letters, and at least one digit and one special character")
	}

	return nil
}

// LoadConfig parses provided JSON configuration file
func LoadConfig(directory string) (Configuration, error) {

	_, err := os.Stat(directory)
	if err != nil {
		return Configuration{}, fmt.Errorf("Config file not found: %s", directory)
	}

	fileContent, err := os.Open(directory)
	if err != nil {
		return Configuration{}, fmt.Errorf("Error opening file: %s", directory)
	}

	defer fileContent.Close()
	byteResult, err := io.ReadAll(fileContent)
	if err != nil {
		return Configuration{}, fmt.Errorf("Error reading file: %s", directory)
	}

	var conf Configuration
	err = json.Unmarshal([]byte(byteResult), &conf)
	if err != nil {
		fmt.Println(err)
		return Configuration{}, fmt.Errorf("Error parsing file: %s", directory)
	}

	return conf, nil
}
