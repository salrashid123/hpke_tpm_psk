package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"
	"main/common"
	"os"
	"slices"

	"github.com/cloudflare/circl/hpke"
	"github.com/google/uuid"
)

var (
	dataToEncrypt = flag.String("dataToEncrypt", "text encrypted to Bob's public key", "Data to encrypt")
	publicKey     = flag.String("publicKey", "certs/public.bin", "public key file ")
	out           = flag.String("out", "certs/out.json", "Output json file ")
	pskBytes      = flag.String("psk", "mypsk", "PSK")
	pskID         = flag.String("pskID", "mypsk-id", "PSK")

	tpmPath = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	pemkey  = flag.String("pemkey", "certs/hmac.pem", "privateKey File")
)

func main() {
	flag.Parse()

	// HPKE suite is a domain parameter.
	kemID := hpke.KEM_P256_HKDF_SHA256
	kdfID := hpke.KDF_HKDF_SHA384
	aeadID := hpke.AEAD_AES256GCM
	suite := hpke.NewSuite(kemID, kdfID, aeadID)

	// if you want to add random value to the "info" data
	id := uuid.New()
	info := append([]byte("public info string, known to both Alice and Bob with nonce "), id.String()...)

	//info := []byte("public info string, known to both Alice and Bob")

	log.Printf("Info: %s\n", info)

	combinedKey := slices.Concat([]byte(*pskID), info)

	// Start standard HMAC
	// key := []byte(*pskBytes)
	// mac := hmac.New(sha256.New, key)
	// mac.Write(combinedKey)
	// psk := mac.Sum(nil)
	// End standard HMAC

	// start TPM HMAC
	psk, err := common.TPMHMAC(*tpmPath, *pemkey, combinedKey)
	if err != nil {
		log.Fatalf("Error runing TPM HMAC: %v", err)
	}
	// end TPM HMAC

	log.Printf("derived PSK: %s\n", base64.StdEncoding.EncodeToString(psk))

	publicBobBinary, err := os.ReadFile(*publicKey)
	if err != nil {
		log.Fatalf("Error reading public key: %v", err)
	}

	publicBob, err := hpke.KEM_P256_HKDF_SHA256.Scheme().UnmarshalBinaryPublicKey(publicBobBinary)
	if err != nil {
		log.Fatalf("Error unmarshalling public b inary: %v", err)
	}

	// Alice gets Bob's public key.
	Alice, err := suite.NewSender(publicBob, info)
	if err != nil {
		log.Fatalf("Error creating sender: %v", err)
	}

	// Alice encrypts some plaintext and sends the ciphertext to Bob.
	ptAlice := []byte(*dataToEncrypt)
	aad := []byte("additional public data")

	enc, sealer, err := Alice.SetupPSK(rand.Reader, psk, []byte(*pskID))
	if err != nil {
		log.Fatalf("Error setting up PSKr: %v", err)
	}

	ct, err := sealer.Seal(ptAlice, aad)
	if err != nil {
		log.Fatalf("Error sealing: %v", err)
	}

	k := &common.KEMToken{
		PSKIdentity:      *pskID,
		CipherText:       ct,
		EncapsulationKey: enc,
		Context:          info,
		AAD:              aad,
	}

	jsonData, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		log.Fatalf("Error MarshalIndent: %v", err)
	}

	// Write JSON data to file
	err = os.WriteFile(*out, jsonData, 0644)
	if err != nil {
		log.Fatalf("Error writing file: %v", err)
	}

}
