package main

import (
	"bufio"
	"crypto/cipher"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/atinyakov/GophKeeper/internal/client/storage"
)

const (
	apiRegister = "/api/register"
	apiSync     = "/api/sync"
)

var (
	version   string
	buildDate string
)

// repl runs the interactive shell loop, accepting commands to manage secrets.
func repl(client *http.Client, baseURL string, ls *storage.LocalStorage, aead cipher.AEAD, nonce []byte) {
	storage.StartAutoSync(client, baseURL, ls)

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("gophkeeper> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		args := strings.Fields(line)
		if len(args) == 0 {
			continue
		}
		switch args[0] {
		case "help":
			fmt.Println("Available commands: help, add, list, get <id>, delete <id>, edit <id>, exit")
		case "add":
			sec := storage.PromptForSecret(aead, nonce)
			ls.Add(sec)
			_ = ls.Save()
		case "list":
			ls.List(aead, nonce)
		case "get":
			if len(args) < 2 {
				fmt.Println("Usage: get <id>")
				continue
			}
			sec := ls.Get(args[1])
			if sec == nil {
				fmt.Println("Secret not found")
			} else {
				b, _ := json.MarshalIndent(sec, "", "  ")
				fmt.Println(string(b))
			}
		case "delete":
			if len(args) < 2 {
				fmt.Println("Usage: delete <id>")
				continue
			}
			if ls.Delete(args[1]) {
				_ = ls.Save()
				fmt.Println("Secret deleted")
			} else {
				fmt.Println("Secret not found")
			}
		case "edit":
			if len(args) < 2 {
				fmt.Println("Usage: edit <id>")
				continue
			}
			newData, newComment := storage.PromptEditSecret()
			if ls.Edit(args[1], newData, newComment, aead, nonce) {
				_ = ls.Save()
				fmt.Println("Secret updated")
			} else {
				fmt.Println("Secret not found")
			}
		case "exit":
			fmt.Println("Bye")
			return
		default:
			fmt.Println("Unknown command. Type 'help' for a list of commands.")
		}
	}
}

// main parses command-line flags and dispatches to the register or shell commands.
func main() {
	var (
		cmd      string
		baseURL  string
		certFile string
		keyFile  string
		caFile   string
		loginStr string
		showVer  bool
	)

	flag.StringVar(&cmd, "cmd", "", "command: register | shell")
	flag.StringVar(&baseURL, "url", "https://localhost:8080", "server base URL")
	flag.StringVar(&certFile, "cert", "client.crt", "path to client cert")
	flag.StringVar(&keyFile, "key", "client.key", "path to client key")
	flag.StringVar(&caFile, "ca", "certs/ca.crt", "path to CA cert")
	flag.StringVar(&loginStr, "login", "", "username for registration")
	flag.BoolVar(&showVer, "version", false, "show build version and date")
	flag.Parse()

	if showVer {
		fmt.Printf("GophKeeper Client\nVersion: %s\nBuild Date: %s\n", version, buildDate)
		return
	}

	switch cmd {
	case "register":
		if loginStr == "" {
			log.Fatal("please provide -login=username")
		}
		if err := storage.Register(baseURL+apiRegister, loginStr, caFile); err != nil {
			log.Fatal(err)
		}
	case "shell":
		client, err := storage.LoadClientCertificate(certFile, keyFile, caFile)
		if err != nil {
			log.Fatal(err)
		}
		ls := &storage.LocalStorage{}
		_ = ls.Load()

		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			log.Fatal(err)
		}
		aead, nonce, err := storage.NewAEADFromPEM(certPEM)
		if err != nil {
			log.Fatal(err)
		}

		repl(client, baseURL, ls, aead, nonce)
	default:
		log.Fatalf("unknown command: %s", cmd)
	}
}
