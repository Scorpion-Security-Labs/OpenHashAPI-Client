// Package main controls the core functions
package main

import (
	"fmt"
	"github.com/Scorpion-Security-Labs/ohaclient/internal/api"
	"github.com/Scorpion-Security-Labs/ohaclient/internal/config"
	"github.com/Scorpion-Security-Labs/ohaclient/internal/models"
	"os"
)

// OHAServerURL holds the URL for functions
var OHAServerURL = ""
var configFile models.Configuration

func init() {

	var err error

	// Try to load from $HOME/.oha
	configFile, err = models.LoadConfig(fmt.Sprintf("%s/.oha", os.Getenv("HOME")))
	if err != nil {
		// Check if the environment variables are set
		if os.Getenv("CLIENT_USERNAME") != "" {
			configFile.ClientUsername = os.Getenv("CLIENT_USERNAME")
		}

		if os.Getenv("SERVER_URL") != "" {
			configFile.ServerURL = os.Getenv("SERVER_URL")
		}

		if os.Getenv("SERVER_PORT") != "" {
			configFile.ServerPort = os.Getenv("SERVER_PORT")
		}

		if os.Getenv("SERVER_API") != "" {
			configFile.ServerAPIRoute = os.Getenv("SERVER_API")
		}

		if os.Getenv("CLIENT_PASSWORD") != "" {
			configFile.ClientPassword = os.Getenv("CLIENT_PASSWORD")
		}

		if os.Getenv("CLIENT_USERNAME") == "" || os.Getenv("SERVER_URL") == "" || os.Getenv("SERVER_PORT") == "" || os.Getenv("SERVER_API") == "" || os.Getenv("CLIENT_PASSWORD") == "" {
			// Values do not exist at all
			// Load the configuration settings from the config file
			fmt.Println(config.PrintColor("[!] Unauthenticated. Please fill out Env vars or place a configuration file at ~/.oha", "red", "%s"))
			os.Exit(1)
		}
	}

	err = models.ValidateConfig(configFile)
	config.CheckError(err)
	OHAServerURL = fmt.Sprintf("https://%s:%s%s", configFile.ServerURL, configFile.ServerPort, configFile.ServerAPIRoute)
}

func main() {
	if len(os.Args) <= 1 {
		printUsage()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "register":
		err := api.RegisterUser(OHAServerURL, configFile.ClientUsername, configFile.ClientPassword)
		config.CheckError(err)
	case "manage":
		if len(os.Args) <= 2 {
			printUsage()
			os.Exit(0)
		}
		uid, err := models.ValidateIntInputArgs(os.Args, 2)
		config.CheckError(err)

		jwt, err := api.ServerAuthenticate(OHAServerURL, configFile.ClientUsername, configFile.ClientPassword)
		config.CheckError(err)

		err = api.ManageUser(OHAServerURL, jwt, uid)
		config.CheckError(err)
	case "search":
		if len(os.Args) <= 2 {
			printUsage()
			os.Exit(0)
		}
		filepath, err := models.ValidateFileInputArgs(os.Args, 2)
		config.CheckError(err)

		jwt, err := api.ServerAuthenticate(OHAServerURL, configFile.ClientUsername, configFile.ClientPassword)
		config.CheckError(err)

		err = api.SearchFounds(OHAServerURL, jwt, filepath)
		config.CheckError(err)
	case "submit":
		if len(os.Args) <= 3 {
			printUsage()
			os.Exit(0)
		}
		algo, err := models.ValidateIntInputArgs(os.Args, 2)
		config.CheckError(err)

		filepath, err := models.ValidateFileInputArgs(os.Args, 3)
		config.CheckError(err)

		jwt, err := api.ServerAuthenticate(OHAServerURL, configFile.ClientUsername, configFile.ClientPassword)
		config.CheckError(err)

		err = api.SubmitFounds(OHAServerURL, jwt, algo, filepath)
		config.CheckError(err)
	case "health":
		jwt, err := api.ServerAuthenticate(OHAServerURL, configFile.ClientUsername, configFile.ClientPassword)
		config.CheckError(err)

		err = api.HealthCheck(OHAServerURL, jwt)
		config.CheckError(err)
	case "status":
		jwt, err := api.ServerAuthenticate(OHAServerURL, configFile.ClientUsername, configFile.ClientPassword)
		config.CheckError(err)

		err = api.StatusCheck(OHAServerURL, jwt)
		config.CheckError(err)
	case "wordlist":
		if len(os.Args) <= 2 {
			printUsage()
			os.Exit(0)
		}

		num, err := models.ValidateIntInputArgs(os.Args, 2)
		config.CheckError(err)

		query, err := models.ValidateQueryStringArgs(os.Args, 3)
		config.CheckError(err)

		jwt, err := api.ServerAuthenticate(OHAServerURL, configFile.ClientUsername, configFile.ClientPassword)
		config.CheckError(err)

		err = api.DownloadResource(OHAServerURL, jwt, "wordlist", num, query)
		config.CheckError(err)
	case "rules":
		if len(os.Args) <= 2 {
			printUsage()
			os.Exit(0)
		}
		num, err := models.ValidateIntInputArgs(os.Args, 2)
		config.CheckError(err)

		query, err := models.ValidateQueryStringArgs(os.Args, 3)
		config.CheckError(err)

		jwt, err := api.ServerAuthenticate(OHAServerURL, configFile.ClientUsername, configFile.ClientPassword)
		config.CheckError(err)

		err = api.DownloadResource(OHAServerURL, jwt, "rules", num, query)
		config.CheckError(err)
	case "masks":
		if len(os.Args) <= 2 {
			printUsage()
			os.Exit(0)
		}
		num, err := models.ValidateIntInputArgs(os.Args, 2)
		config.CheckError(err)

		query, err := models.ValidateQueryStringArgs(os.Args, 3)
		config.CheckError(err)

		jwt, err := api.ServerAuthenticate(OHAServerURL, configFile.ClientUsername, configFile.ClientPassword)
		config.CheckError(err)

		err = api.DownloadResource(OHAServerURL, jwt, "masks", num, query)
		config.CheckError(err)
	case "lists":
		jwt, err := api.ServerAuthenticate(OHAServerURL, configFile.ClientUsername, configFile.ClientPassword)
		config.CheckError(err)

		if len(os.Args) <= 2 {
			api.ListAllPrivateLists(OHAServerURL, jwt)
			os.Exit(0)
		}

		filename, err := models.ValidateQueryStringArgs(os.Args, 2)
		config.CheckError(err)

		err = api.ListTargetPrivateList(OHAServerURL, jwt, filename)
		config.CheckError(err)
	case "create":
		jwt, err := api.ServerAuthenticate(OHAServerURL, configFile.ClientUsername, configFile.ClientPassword)
		config.CheckError(err)

		if len(os.Args) <= 2 {
			printUsage()
			os.Exit(0)
		}
		filename, err := models.ValidateQueryStringArgs(os.Args, 2)
		config.CheckError(err)

		newfile, err := models.ValidateQueryStringArgs(os.Args, 3)
		config.CheckError(err)

		err = api.CreateNewPrivateList(OHAServerURL, jwt, newfile, filename)
		config.CheckError(err)

	case "update":
		jwt, err := api.ServerAuthenticate(OHAServerURL, configFile.ClientUsername, configFile.ClientPassword)
		config.CheckError(err)

		if len(os.Args) <= 2 {
			printUsage()
			os.Exit(0)
		}

		filename, err := models.ValidateQueryStringArgs(os.Args, 2)
		config.CheckError(err)

		listname, err := models.ValidateQueryStringArgs(os.Args, 3)
		config.CheckError(err)

		err = api.UpdateTargetPrivateList(OHAServerURL, jwt, filename, listname)
		config.CheckError(err)

	default:
		printUsage()
		os.Exit(0)
	}
}

func printUsage() {
	fmt.Println(config.PrintColor("[+] OHA Client Configuration Settings:", "yellow", "%s"))
	fmt.Println(config.PrintColor(fmt.Sprintf("OHA User: %s", configFile.ClientUsername), "green", "%s"))
	fmt.Println(config.PrintColor(fmt.Sprintf("OHA Server URL: %s:%s", configFile.ServerURL, configFile.ServerPort), "green", "%s"))
	fmt.Println(config.PrintColor(fmt.Sprintf("OHA Server API URL: %s:%s%s", configFile.ServerURL, configFile.ServerPort, configFile.ServerAPIRoute), "green", "%s"))
	fmt.Println(config.PrintColor("[+] Available Commands:", "yellow", "%s"))
	fmt.Println(config.PrintColor("register:", "cyan", "%s"), "Attempts user registration on the OHA Server.")
	fmt.Println(config.PrintColor("manage:", "cyan", "%s"), "Changes user permissions for target user.")
	fmt.Println(config.PrintColor("search:", "cyan", "%s"), "Searches the OHA Server for any matching HASH values in a file.")
	fmt.Println(config.PrintColor("submit:", "cyan", "%s"), "Submit a file containing HASH:PLAIN values to the OHA Server.")
	fmt.Println(config.PrintColor("health:", "cyan", "%s"), "Requests the OHA Server settings then prints them.")
	fmt.Println(config.PrintColor("status:", "cyan", "%s"), "Check the status of downloadable files on the OHA Server.")
	fmt.Println(config.PrintColor("wordlist:", "cyan", "%s"), "Downloads portions of the wordlist file from the OHA Server.")
	fmt.Println(config.PrintColor("rules:", "cyan", "%s"), "Downloads portions of the rules file from the OHA Server.")
	fmt.Println(config.PrintColor("masks:", "cyan", "%s"), "Downloads portions of the masks file from the OHA Server.")
	fmt.Println(config.PrintColor("lists:", "cyan", "%s"), "View or downloads the available lists on the OHA Server.")
	fmt.Println(config.PrintColor("create:", "cyan", "%s"), "Create a new private list on the OHA Server.")
	fmt.Println(config.PrintColor("update:", "cyan", "%s"), "Updates the target list on the OHA Server.")
	fmt.Println(config.PrintColor("[+] Example Commands:", "yellow", "%s"))
	fmt.Println(config.PrintColor("register:", "cyan", "%s"), "ohaclient register")
	fmt.Println(config.PrintColor("manage:", "cyan", "%s"), "ohaclient manage UID")
	fmt.Println(config.PrintColor("search:", "cyan", "%s"), "ohaclient search FILE")
	fmt.Println(config.PrintColor("submit:", "cyan", "%s"), "ohaclient found ALGO FILE")
	fmt.Println(config.PrintColor("health:", "cyan", "%s"), "ohaclient health")
	fmt.Println(config.PrintColor("status:", "cyan", "%s"), "ohaclient status")
	fmt.Println(config.PrintColor("wordlist:", "cyan", "%s"), "ohaclient wordlist NUM [QUERY-STRING]")
	fmt.Println(config.PrintColor("rules:", "cyan", "%s"), "ohaclient rules NUM [QUERY-STRING]")
	fmt.Println(config.PrintColor("masks:", "cyan", "%s"), "ohaclient masks NUM [QUERY-STRING]")
	fmt.Println(config.PrintColor("lists:", "cyan", "%s"), "ohaclient lists or ohaclient lists LISTNAME")
	fmt.Println(config.PrintColor("create:", "cyan", "%s"), "ohaclient create LISTNAME FILE")
	fmt.Println(config.PrintColor("update:", "cyan", "%s"), "ohaclient update LISTNAME FILE")
}
