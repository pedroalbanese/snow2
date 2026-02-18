package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/pedroalbanese/snow2"
)

var (
	file    = flag.String("f", "", "Target file. ('-' for STDIN)")
	key     = flag.String("k", "", "Symmetric key (hex) (16/32 bytes)")
	nonce   = flag.String("n", "", "Nonce/IV (hex) (16 bytes)")
	random  = flag.Bool("r", false, "Generate random key (32 bytes) and nonce (16 bytes)")
)

func main() {
	flag.Parse()

	if *random {
		keyBytes := make([]byte, 32)
		nonceBytes := make([]byte, 16)
		rand.Read(keyBytes)
		rand.Read(nonceBytes)
		fmt.Printf("Key: %s\n", hex.EncodeToString(keyBytes))
		fmt.Printf("Nonce: %s\n", hex.EncodeToString(nonceBytes))
		return
	}

	if *key == "" || *nonce == "" {
		fmt.Fprintln(os.Stderr, "SNOW 2.0 Stream Cipher")
		fmt.Fprintln(os.Stderr, "Usage: "+os.Args[0]+" -k <keyhex> -n <noncehex> -f <file>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	keyBytes, err := hex.DecodeString(*key)
	if err != nil || len(keyBytes) > 32 {
		log.Fatal("Invalid key")
	}

	nonceBytes, err := hex.DecodeString(*nonce)
	if err != nil || len(nonceBytes) > 16 {
		log.Fatal("Invalid nonce")
	}

	var data io.Reader
	if *file == "-" {
		data = os.Stdin
	} else {
		f, err := os.Open(*file)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		data = f
	}

	ciph, _ := snow2.NewCipher(keyBytes, nonceBytes)
	buf := make([]byte, 64*1<<10)
	var n int
	for {
		n, err = data.Read(buf)
		if err != nil && err != io.EOF {
			log.Fatal(err)
		}
		ciph.XORKeyStream(buf[:n], buf[:n])
		if _, err := os.Stdout.Write(buf[:n]); err != nil {
			log.Fatal(err)
		}
		if err == io.EOF {
			break
		}
	}
	os.Exit(0)
}
