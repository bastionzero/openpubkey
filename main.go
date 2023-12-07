package main

import (
	"context"
	"crypto"
	"encoding/pem"
	"errors"
	"fmt"
	"freessh/commands"
	"freessh/internal"
	"freessh/policy"
	"freessh/sshcert"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/pktoken"
	"golang.org/x/crypto/ssh"
)

// This code is currently intended as an example for how OpenPubkey can secure
// SSH access.
func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Example SSH key generator using OpenPubkey: command choices are: login, ver")
		return
	}
	command := os.Args[1]

	// OIDC provider is hardcoded to Google for now
	op := internal.GoogleOp

	switch command {
	case "login":
		if len(os.Args) != 2 {
			fmt.Println("ERROR login does not accept any arguments")
			os.Exit(1)
		}

		// Execute login command
		err := commands.Login(&op)
		if err != nil {
			fmt.Printf("login error: %v", err)
			os.Exit(1)
		}

		os.Exit(0)
	case "verify":
		// Setup logger
		logPath := "/var/log/openpubkey.log"
		logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0700)
		if err != nil {
			fmt.Println("ERROR opening log file:", err)
			os.Exit(1)
		}
		defer logFile.Close()
		log.SetOutput(logFile)

		// The "verify" command is designed to be used by sshd and specified as an AuthorizedKeysCommand
		// ref: https://man.openbsd.org/sshd_config#AuthorizedKeysCommand
		{
			log.Println(strings.Join(os.Args, " "))
			policyEnforcer := policy.Enforcer{
				PolicyFilePath: "/etc/opk/policy",
			}

			// These arguments are sent by sshd and dictated by the pattern as defined in the sshd config
			// Example line in sshd config:
			// 		AuthorizedKeysCommand /etc/opk/freessh verify %u %k %t
			//
			//	%u The desired user being assumed on the target (aka requested principal).
			//	%k The base64-encoded public key for authentication.
			//	%t The public key type, in this case an ssh certificate being used as a public key.
			if len(os.Args) != 5 {
				fmt.Println("Invalid number of arguments for verify, expected: `<User (TOKEN u)> <Key type (TOKEN t)> <Cert (TOKEN k)>`")
				os.Exit(1)
			}
			user := os.Args[2]
			certB64 := os.Args[3]
			pubkeyType := os.Args[4]

			authKey, err := authorizedKeysCommand(user, certB64, pubkeyType, policyEnforcer.CheckPolicy, &op)
			if err != nil {
				log.Println(err)
				os.Exit(1)
			} else {
				fmt.Println(authKey)
				os.Exit(0)
			}
		}
	default:
		fmt.Println("ERROR! Unrecognized command:", command)
	}
}

func authorizedKeysCommand(
	userArg string,
	certB64Arg string,
	pubkeyTypeArg string,
	policyCheck func(userDesired string, pkt *pktoken.PKToken) error,
	op client.OpenIdProvider,
) (string, error) {
	cert, err := sshcert.NewFromAuthorizedKey(pubkeyTypeArg, certB64Arg)
	if err != nil {
		return "", err
	}
	if pkt, err := cert.VerifySshPktCert(op); err != nil {
		return "", err
	} else if err := policyCheck(userArg, pkt); err != nil {
		return "", err
	} else {
		// sshd expects the public key in the cert, not the cert itself.
		// This public key is key of the CA the signs the cert, in our
		// setting there is no CA.
		pubkeyBytes := ssh.MarshalAuthorizedKey(cert.SshCert.SignatureKey)
		return "cert-authority " + string(pubkeyBytes), nil
	}
}

func createSSHCert(cxt context.Context, client *client.OpkClient, signer crypto.Signer, alg jwa.KeyAlgorithm, gqFlag bool, principals []string) ([]byte, []byte, error) {
	pkt, err := client.OidcAuth(cxt, signer, alg, map[string]any{}, gqFlag)
	if err != nil {
		return nil, nil, err
	}
	cert, err := sshcert.New(pkt, principals)
	if err != nil {
		return nil, nil, err
	}
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, nil, err
	}

	signerMas, err := ssh.NewSignerWithAlgorithms(sshSigner.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoECDSA256})
	if err != nil {
		return nil, nil, err
	}

	sshCert, err := cert.SignCert(signerMas)
	if err != nil {
		return nil, nil, err
	}
	certBytes := ssh.MarshalAuthorizedKey(sshCert)

	seckeySsh, err := ssh.MarshalPrivateKey(signer, "openpubkey cert")
	if err != nil {
		return nil, nil, err
	}
	seckeySshBytes := pem.EncodeToMemory(seckeySsh)

	return certBytes, seckeySshBytes, nil
}

func writeKeysToSSHDir(seckeySshPem []byte, certBytes []byte) error {
	homePath, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	sshPath := filepath.Join(homePath, ".ssh")

	//  For ssh to automatically find the key created by openpubkey when connecting, we use
	// one of the default ssh key paths. However, the file might contain an existing key. We
	// will overwrite the key if it was generated by openpubkey which we check by looking at
	// the associated comment. If the comment is equal to "openpubkey", we overwrite the file
	// with a new key.
	for _, keyFilename := range []string{"id_ecdsa", "id_dsa"} {
		seckeyPath := filepath.Join(sshPath, keyFilename)
		pubkeyPath := seckeyPath + ".pub"

		if !fileExists(seckeyPath) {
			// If ssh key file does not currently exist, we don't have to worry about overwriting it
			return writeKeys(seckeyPath, pubkeyPath, seckeySshPem, certBytes)
		} else if !fileExists(pubkeyPath) {
			continue
		} else {
			// If the ssh key file does exist, check if it was generated by openpubkey, if it was then it is safe to overwrite
			sshPubkey, err := os.ReadFile(pubkeyPath)
			if err != nil {
				fmt.Println("Failed to read:", pubkeyPath)
				continue
			}
			sshPubkeySplit := strings.Split(string(sshPubkey), " ")
			if len(sshPubkeySplit) != 3 {
				fmt.Println("Failed to parse:", pubkeyPath)
				continue
			}

			// If the key comment is "openpubkey" then we generated it
			if strings.Contains(sshPubkeySplit[2], ("openpubkey")) {
				return writeKeys(seckeyPath, pubkeyPath, seckeySshPem, certBytes)
			}
		}
	}
	return fmt.Errorf("no default ssh key file free for openpubkey")
}

func writeKeys(seckeyPath string, pubkeyPath string, seckeySshPem []byte, certBytes []byte) error {
	// Write ssh secret key to filesystem
	if err := os.WriteFile(seckeyPath, seckeySshPem, 0600); err != nil {
		return err
	}

	fmt.Println("writing secret key to", seckeyPath)
	fmt.Println("writing public key to", pubkeyPath)

	certBytes = append(certBytes, []byte(" openpubkey")...)
	// Write ssh public key (certificate) to filesystem
	return os.WriteFile(pubkeyPath, certBytes, 0777)
}

func fileExists(fPath string) bool {
	_, err := os.Open(fPath)
	return !errors.Is(err, os.ErrNotExist)
}

// Retrieve an open port
func retrieveOpenPort() (port int, err error) {
	for index, port := range avilableURIPorts {
		fmt.Printf(strconv.Itoa(index), port)
		available, err := checkPortIsAvailable(port)
		if err != nil {
			fmt.Printf("Port %v is not available.", port)
		} else if available {
			return port, nil
		}
	}

	return 0, fmt.Errorf("failed to retrieve open port: callback listener could not bind to any of the default ports")
}

// Reference -> https://gist.github.com/montanaflynn/b59c058ce2adc18f31d6
// Check if a port is available
func checkPortIsAvailable(port int) (status bool, err error) {

	// Concatenate a colon and the port
	host := fmt.Sprintf(":%d", port)

	// Try to create a server with the port
	server, err := net.Listen("tcp", host)

	// if it fails then the port is likely taken
	if err != nil {
		return false, err
	}

	// close the server
	server.Close()

	// we successfully used and closed the port
	// so it's now available to be used again
	return true, nil

}
