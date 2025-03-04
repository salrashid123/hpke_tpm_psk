package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"
	"main/common"
	"os"
	"slices"

	"github.com/cloudflare/circl/hpke"
)

var (
	privateKey = flag.String("privateKey", "certs/private.bin", "private key file ")
	in         = flag.String("in", "certs/out.json", "Encrypted json")
	pskBytes   = flag.String("psk", "mypsk", "PSK")

	tpmPath = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	pemkey  = flag.String("pemkey", "certs/hmac.pem", "privateKey File")
)

func main() {
	flag.Parse()

	pkey, err := os.ReadFile(*privateKey)
	if err != nil {
		log.Fatalf("Error reading private key: %v", err)
	}

	inBytes, err := os.ReadFile(*in)
	if err != nil {
		log.Fatalf("Error reading encapsulation key: %v", err)
	}

	var k common.KEMToken
	err = json.Unmarshal(inBytes, &k)
	if err != nil {
		log.Fatal(err)
	}

	// HPKE suite is a domain parameter.
	kemID := hpke.KEM_P256_HKDF_SHA256
	kdfID := hpke.KDF_HKDF_SHA384
	aeadID := hpke.AEAD_AES256GCM
	suite := hpke.NewSuite(kemID, kdfID, aeadID)

	log.Printf("Info: %s\n", k.Context)

	pskID := []byte(k.PSKIdentity)

	combinedKey := slices.Concat(pskID, k.Context)

	// standard HMAC
	// key := []byte(*pskBytes)
	// mac := hmac.New(sha256.New, key)
	// mac.Write(combinedKey)
	// psk := mac.Sum(nil)

	// start TPM HMAC
	psk, err := common.TPMHMAC(*tpmPath, *pemkey, combinedKey)
	if err != nil {
		log.Fatalf("Error runing TPM HMAC: %v", err)
	}
	// end TPM HMAC

	log.Printf("derived PSK: %s\n", base64.StdEncoding.EncodeToString(psk))

	privateBob, err := hpke.KEM_P256_HKDF_SHA256.Scheme().UnmarshalBinaryPrivateKey(pkey)
	if err != nil {
		log.Fatalf("Error unmarshalling public binary: %v", err)
	}

	Bob, err := suite.NewReceiver(privateBob, k.Context)
	if err != nil {
		log.Fatalf("Error error creating NewReceiver: %v", err)
	}

	opener, err := Bob.SetupPSK(k.EncapsulationKey, psk, pskID)
	if err != nil {
		log.Fatalf("Error setupPSK: %v", err)
	}
	ptBob, err := opener.Open(k.CipherText, k.AAD)
	if err != nil {
		log.Fatalf("Error open: %v", err)
	}

	log.Printf("Decrypted [%s]\n", ptBob)
}
