package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/bastionzero/opk-ssh/commands"
	"github.com/bastionzero/opk-ssh/policy"
	"github.com/bastionzero/opk-ssh/provider"
)

var (
	issuer           = "https://accounts.google.com"
	clientID         = "878305696756-dd5ns57fccufrruii19fd7ed6jpd155r.apps.googleusercontent.com"
	clientSecret     = "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"
	redirectEndpoint = "/login-callback"
	redirectURIPorts = []int{49172, 51252, 58243, 59360, 62109}
)

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		fmt.Println("Example SSH key generator using OpenPubkey: command choices are: login, verify, and add")
		return 1
	}
	command := os.Args[1]

	provider, err := provider.NewGoogleProvider(issuer, clientID, clientSecret, redirectURIPorts, redirectEndpoint, nil, true, nil)
	if err != nil {
		log.Println("failed to create new google provider instance:", err)
		return 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		cancel()
	}()

	switch command {
	case "login":
		loginCmd := flag.NewFlagSet("login", flag.ExitOnError)
		autoRefresh := loginCmd.Bool("auto-refresh", false, "Used to specify whether login will begin a process that auto-refreshes PK token")
		logFilePath := loginCmd.String("log-dir", "", "Specify which directory the output log is placed")
		loginCmd.Parse(os.Args[2:])

		// If a log directory was provided, write any logs to a file in that directory AND stdout
		if *logFilePath != "" {
			logFilePath := filepath.Join(*logFilePath, "openpubkey.log")
			logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0700)
			if err == nil {
				defer logFile.Close()
				multiWriter := io.MultiWriter(os.Stdout, logFile)
				log.SetOutput(multiWriter)
			}
		}

		// Execute login command
		if *autoRefresh {
			err = commands.LoginWithRefresh(ctx, provider)
		} else {
			err = commands.Login(ctx, provider)
		}

		if err != nil {
			log.Println("ERROR logging in:", err)
			return 1
		}
	case "verify":
		// Setup logger
		logFile, err := os.OpenFile("/var/log/openpubkey.log", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0700)
		if err != nil {
			fmt.Println("ERROR opening log file:", err)
		} else {
			defer logFile.Close()
			log.SetOutput(logFile)
		}

		// The "verify" command is designed to be used by sshd and specified as an AuthorizedKeysCommand
		// ref: https://man.openbsd.org/sshd_config#AuthorizedKeysCommand
		log.Println(strings.Join(os.Args, " "))

		// These arguments are sent by sshd and dictated by the pattern as defined in the sshd config
		// Example line in sshd config:
		// 		AuthorizedKeysCommand /etc/opk/opk-ssh verify %u %k %t
		//
		//	%u The desired user being assumed on the target (aka requested principal).
		//	%k The base64-encoded public key for authentication.
		//	%t The public key type, in this case an ssh certificate being used as a public key.
		if len(os.Args) != 5 {
			log.Println("Invalid number of arguments for verify, expected: `<User (TOKEN u)> <Key type (TOKEN t)> <Cert (TOKEN k)>`")
			return 1
		}
		userArg := os.Args[2]
		certB64 := os.Args[3]
		pubkeyType := os.Args[4]

		// Execute verify command
		v := commands.VerifyCmd{
			OPConfig: provider,
			Auth:     commands.OpkPolicyEnforcerAsAuthFunc(userArg),
		}
		if authKey, err := v.Verify(ctx, userArg, certB64, pubkeyType); err != nil {
			log.Println("failed to verify:", err)
			return 1
		} else {
			// sshd is awaiting a specific line, which we print here. Printing anything else before or after will break our solution
			fmt.Println(authKey)
		}
	case "add":
		// The "add" command is designed to be used by the client configuration
		// script to inject user entries into the policy file
		//
		// Example line to add a user:
		// 		./opk-ssh add %e %p
		//
		//  %e The email of the user to be added to the policy file.
		//	%p The desired principal being assumed on the target (aka requested principal).
		if len(os.Args) != 4 {
			fmt.Println("Invalid number of arguments for verify, expected: `<Email (TOKEN e)> <Principal (TOKEN p)>`")
			return 1
		}
		inputEmail := os.Args[2]
		inputPrincipal := os.Args[3]

		// Execute add command
		a := commands.AddCmd{
			PolicyFileLoader: policy.NewFileLoader(),
			Username:         inputPrincipal,
		}
		if policyFilePath, err := a.Add(inputEmail, inputPrincipal); err != nil {
			log.Println("failed to add to policy:", err)
			return 1
		} else {
			log.Println("Successfully added new policy to", policyFilePath)
		}
	default:
		log.Println("ERROR! Unrecognized command:", command)
		return 1
	}

	return 0
}
