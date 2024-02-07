// Package config holds utilities for the client
package config

import (
	"fmt"
	"math/rand"
	"os"
)

// PrintColor controls printing colored text to the CLI
//
// if no color is provided a random one is rolled
func PrintColor(s interface{}, c string, t string) string {
	s = fmt.Sprintf(t, s)
	switch c {
	case "red":
		return fmt.Sprintf("\x1b[%dm%s\x1b[0m", 31, s)
	case "green":
		return fmt.Sprintf("\x1b[%dm%s\x1b[0m", 32, s)
	case "yellow":
		return fmt.Sprintf("\x1b[%dm%s\x1b[0m", 33, s)
	case "blue":
		return fmt.Sprintf("\x1b[%dm%s\x1b[0m", 34, s)
	case "magenta":
		return fmt.Sprintf("\x1b[%dm%s\x1b[0m", 35, s)
	case "cyan":
		return fmt.Sprintf("\x1b[%dm%s\x1b[0m", 36, s)
	default:
		return fmt.Sprintf("\x1b[%dm%s\x1b[0m", rand.Intn(36-31+1)+31, s)
	}
}

// CheckError is a general error handler
func CheckError(err error) {
	if err != nil {
		fmt.Println(PrintColor(fmt.Sprintf("error: %s\n", err), "red", "%s"))
		os.Exit(1)
	}
}
