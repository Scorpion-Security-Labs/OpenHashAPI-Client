// Package api contains logic for communicating with the server API
package api

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/Scorpion-Security-Labs/ohaclient/internal/config"
	"github.com/Scorpion-Security-Labs/ohaclient/internal/models"
)

// PostRequest sends an HTTP POST request to the specified URL and route with the given data.
//
// If auth is true, an Authorization header is added to the request.
//
// The function returns the response body as a byte slice and any error that occurred.
func PostRequest(url string, route string, data string, jwt string) ([]byte, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: tr}

	reqURL := fmt.Sprintf("%s%s", url, route)
	req, err := http.NewRequest(http.MethodPost, reqURL, strings.NewReader(data))
	if err != nil {
		return nil, err
	}

	if jwt != "" {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", jwt))
	}

	req.Header.Add("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	return resBody, nil
}

// GetRequest sends an HTTP GET request to the specified URL and route.
//
// If a jwt is provided, an Authorization header is added to the request.
//
// The function returns the response body as a byte slice and any error that occurred.
func GetRequest(url string, route string, jwt string) ([]byte, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: tr}

	reqURL := fmt.Sprintf("%s%s", url, route)
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	if jwt != "" {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", jwt))
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	return resBody, nil
}

// ServerAuthenticate sends a POST request to the /api/login route of the specified URL
// with the credentials stored in the environment variables.
//
// The function returns a valid JWT as a string and any error that occurred.
func ServerAuthenticate(url string, username string, password string) (string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: tr}

	jsondata := &models.UserCredentials{Username: username, Password: password}
	encjson, err := json.Marshal(jsondata)
	if err != nil {
		return "", err
	}

	reqURL := fmt.Sprintf("%s%s", url, "/login")
	req, err := http.NewRequest(http.MethodPost, reqURL, bytes.NewBuffer(encjson))
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	var body map[string]interface{}
	if err := json.Unmarshal(resBody, &body); err != nil {
		return "", err
	}

	if body["error"] != nil {
		return "", errors.New("username or password is incorrect")
	}
	return fmt.Sprintf("%v", body["token"]), nil
}

// RegisterUser sends a POST request to the /api/register route of the specified URL
// with the credentials stored in the environment variables.
//
// The function prints the response body and returns any error that occurred.
func RegisterUser(url string, username string, password string) error {
	jsondata := &models.UserCredentials{Username: username, Password: password}
	encjson, err := json.Marshal(jsondata)
	if err != nil {
		return err
	}
	res, err := PostRequest(url, "/register", string(encjson), "")
	if err != nil {
		return err
	}
	fmt.Println(string(res))
	return nil
}

// ManageUser sends a POST request to the /api/manage route of the specified
// URL.
//
// The function prints the response body and returns any error that occured.
func ManageUser(url string, jwt string, uid string) error {
	uidInt, err := strconv.Atoi(uid)
	config.CheckError(err)

	reader := bufio.NewReader(os.Stdin)
	userPermissions := models.UserPermissions{UserID: uidInt}
	permissions := []string{"CanLogin", "CanUpload", "CanSearch", "CanManage"}
	for _, permission := range permissions {
		fmt.Printf("Change permission for %s to true? (y/n): ", permission)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))
		if input == "y" || input == "yes" {
			switch permission {
			case "CanLogin":
				userPermissions.CanLogin = true
			case "CanUpload":
				userPermissions.CanUpload = true
			case "CanSearch":
				userPermissions.CanSearch = true
			case "CanManage":
				userPermissions.CanManage = true
			}
			fmt.Printf("Permission for %s changed.\n", permission)
		} else {
			fmt.Printf("Permission for %s not changed.\n", permission)
		}
	}
	encjson, err := json.Marshal(userPermissions)
	if err != nil {
		return err
	}

	res, err := PostRequest(url, "/manage", string(encjson), jwt)
	if err != nil {
		return err
	}
	fmt.Println(string(res))
	return nil
}

// HealthCheck sends a GET request to the /api/health route of the specified URL.
//
// The function prints the response body and returns any error that occurred.
func HealthCheck(url string, jwt string) error {
	res, err := GetRequest(url, "/health", jwt)
	if err != nil {
		return err
	}

	var obj map[string]interface{}
	err = json.Unmarshal([]byte(res), &obj)
	if err != nil {
		panic(err)
	}
	pretty, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(pretty))
	return nil
}

// StatusCheck sends a GET request to the /api/status route of the specified URL.
//
// The function prints the response body and returns any error that occurred.
func StatusCheck(url string, jwt string) error {
	res, err := GetRequest(url, "/status", jwt)
	if err != nil {
		return err
	}
	fmt.Println(string(res))
	return nil
}

// SubmitFounds sends a POST request to the /api/found route of the specified URL
// with the hashes read from the specified file and the given algorithm.
//
// The function prints the response body and returns any error that occurred.
func SubmitFounds(url string, jwt string, alg string, infile string) error {
	buf, err := os.Open(infile)
	if err != nil {
		return err
	}
	defer func() {
		if err = buf.Close(); err != nil {
			fmt.Printf("Error: %s\n", err)
			os.Exit(0)
		}
	}()

	filescanner := bufio.NewScanner(buf)
	if err := filescanner.Err(); err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(0)
	}
	var fileHashes []string
	for filescanner.Scan() {
		fileHashes = append(fileHashes, filescanner.Text())
	}
	jsondata := &models.UploadHashes{Algorithm: fmt.Sprintf("%s", alg), HashPlain: fileHashes}
	encjson, err := json.Marshal(jsondata)
	if err != nil {
		return err
	}

	res, err := PostRequest(url, "/found", string(encjson), jwt)
	if err != nil {
		return err
	}
	fmt.Println(string(res))
	return nil
}

// SearchFounds sends a POST request to the /api/search route of the specified URL
// with the hashes read from the specified file.
//
// The function prints the found hashes and their plaintext values and returns any error that occurred.
func SearchFounds(url string, jwt string, infile string) error {
	buf, err := os.Open(infile)
	if err != nil {
		return err
	}
	defer func() {
		if err = buf.Close(); err != nil {
			fmt.Printf("Error: %s\n", err)
			os.Exit(0)
		}
	}()

	filescanner := bufio.NewScanner(buf)
	if err := filescanner.Err(); err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(0)
	}
	var fileHashes []string
	for filescanner.Scan() {
		fileHashes = append(fileHashes, filescanner.Text())
	}
	jsondata := &models.SearchHashes{Data: fileHashes}
	encjson, err := json.Marshal(jsondata)
	if err != nil {
		return err
	}

	res, err := PostRequest(url, "/search", string(encjson), jwt)
	if err != nil {
		return err
	}

	var body map[string]interface{}
	json.Unmarshal(res, &body)

	if body["found"] == "[]" {
		fmt.Println("")
	} else {
		for _, c := range body["found"].([]interface{}) {
			a := c.(map[string]interface{})["algorithm"]
			h := c.(map[string]interface{})["hash"]
			p := c.(map[string]interface{})["plaintext"]

			fmt.Println(fmt.Sprintf("%s | %s:%s", a, h, p))
		}
	}
	return nil
}

// DownloadResource sends a POST request to the /api/download/FILE/NUm route of
// the specified URL
//
// The function prints lines from the files and returns any error that occured.
func DownloadResource(url string, jwt string, path string, num string, query string) error {
	fullPath := fmt.Sprintf("/download/%s/%s?%s", path, num, query)
	res, err := GetRequest(url, fullPath, jwt)
	if err != nil {
		return err
	}
	fmt.Println(string(res))
	return nil
}

// ListAllPublicLists sends a GET request to the /api/list route of the specified URL.
//
// The function prints the response body and returns any error that occurred.
func ListAllPrivateLists(url string, jwt string) error {
	fullPath := fmt.Sprintf("/lists")
	res, err := GetRequest(url, fullPath, jwt)
	if err != nil {
		return err
	}

	var body map[string]interface{}
	json.Unmarshal(res, &body)
	fmt.Println(config.PrintColor("Private Files Listing:", "yellow", "%s"))
	for _, c := range body["files"].([]interface{}) {
		fmt.Println(config.PrintColor(fmt.Sprintf("Name: %s | Size: %.0f | Created: %s", c.(map[string]interface{})["name"], c.(map[string]interface{})["size"], c.(map[string]interface{})["creation_time"]), "green", "%s"))
	}

	return nil
}

// ListTargetPublicList sends a GET request to the /api/list/LISTNAME route of the specified URL.
//
// The function prints the response body and returns any error that occurred.
func ListTargetPrivateList(url string, jwt string, listname string) error {
	fullPath := fmt.Sprintf("/lists/%s", listname)
	res, err := GetRequest(url, fullPath, jwt)
	if err != nil {
		return err
	}
	fmt.Println(string(res))
	return nil
}

// CreateNewPublicList sends a POST request to the /api/lists route of the specified URL
//
// Content-Type: text/plain
// The function prints the response body and returns any error that occurred.
func CreateNewPrivateList(url string, jwt string, infile string, filename string) error {
	fileContent, err := os.ReadFile(infile)
	if err != nil {
		return err
	}

	res, err := PostRequest(url, fmt.Sprintf("/lists?name=%s", filename), string(fileContent), jwt)
	if err != nil {
		return err
	}

	fmt.Println(string(res))
	return nil
}

// UpdateTargetPublicList sends a POST request to the /api/lists/LISTNAME route of the specified URL
//
// Content-Type: text/plain
// The function prints the response body and returns any error that occurred.
func UpdateTargetPrivateList(url string, jwt string, listname string, infile string) error {
	fileContent, err := os.ReadFile(infile)
	if err != nil {
		return err
	}

	res, err := PostRequest(url, fmt.Sprintf("/lists/%s", listname), string(fileContent), jwt)
	if err != nil {
		return err
	}

	fmt.Println(string(res))
	return nil
}
