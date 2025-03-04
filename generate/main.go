package main

import (
	"flag"
	"log"
	"os"

	"github.com/cloudflare/circl/hpke"
)

var (
	publicKey  = flag.String("publicKey", "certs/public.bin", "public key file ")
	privateKey = flag.String("privateKey", "certs/private.bin", "privateKey File")
)

func main() {
	flag.Parse()

	// HPKE suite is a domain parameter.
	kemID := hpke.KEM_P256_HKDF_SHA256

	log.Printf("Generating key of type %s\n", kemID.Scheme().Name())

	// Bob prepares to receive messages and announces his public key.
	publicBob, privateBob, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		log.Fatalf("Error generating keyhpair: %v", err)
	}

	publicBobBinary, err := publicBob.MarshalBinary()
	if err != nil {
		log.Fatalf("Error marshaling public key: %v", err)
	}

	err = os.WriteFile(*publicKey, publicBobBinary, 0644)
	if err != nil {
		log.Fatalf("Error writing public key: %v", err)
	}

	pbin, err := privateBob.MarshalBinary()
	if err != nil {
		log.Fatalf("Error marshaling private key: %v", err)
	}

	err = os.WriteFile(*privateKey, pbin, 0644)
	if err != nil {
		log.Fatalf("Error writing private key key: %v", err)
	}
	log.Printf("Public key written to %s\n", *publicKey)
	log.Printf("Private key written to %s\n", *privateKey)
}
