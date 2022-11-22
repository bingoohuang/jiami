package main

import (
	"encoding/base64"
	"log"
	"os"

	"github.com/bingoohuang/jiami"
	"github.com/spf13/pflag"
	"github.com/vmihailenco/msgpack/v5"
)

func main() {
	input := pflag.StringP("input", "i", "", "input string")
	passphrase := pflag.StringP("passphrase", "p", "", "passphrase")
	pflag.Parse()

	d, err := base64.StdEncoding.DecodeString(*input)
	if err != nil {
		log.Fatalf("base64.StdEncoding.DecodeString failed: %v", err)
	}

	encoded := &jiami.Encoded{}
	if err := msgpack.Unmarshal(d, encoded); err != nil {
		log.Fatalf("msgpack.Unmarshal failed: %v", err)
	}

	if *passphrase == "" {
		*passphrase = os.Getenv("PASSPHRASE")
	}

	key := &jiami.Key{Passphrase: []byte(*passphrase), Salt: encoded.Salt}
	if err := key.Init(); err != nil {
		log.Fatalf("key.Init failed: %v", err)
	}

	plain, err := jiami.NewAesGcm().Decrypt(key, encoded)
	if err != nil {
		log.Fatalf("Decrypt failed: %v", err)
	}

	log.Printf("Plain: %s", plain)
}
