package main

import (
	"bytes"
	"io"

	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
	"golang.org/x/crypto/openpgp/armor"
)

func main() {
	messageHex := "29bf7021020ea89dbd91ef52022b5a654b55ed418c9e7aba71ef3b43a51669f2" // keccak256(hello, world) in hex
	message, err := hex.DecodeString(messageHex)
	if err != nil {
		fmt.Printf("Failed to decode messageHex: %v\n", err)
		return
	}

	armoredPublicKey := `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEZ2pdDhYJKwYBBAHaRw8BAQdAXRCrGQMPij7crOE9DhZjZ9KV8eEU74fI8wCc
2pMaDuu0K0tyaXNoYW5nIE5hZGdhdWRhIDxrcmlzaGFuZy5ub3RlQGdtYWlsLmNv
bT6IkwQTFgoAOxYhBMDC3NihB0bkfHWxgZZ2cvhFREO4BQJnal0OAhsDBQsJCAcC
AiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEJZ2cvhFREO4IkIA/3XEValP5MgubFFv
UjrsGdQoV/F6dOHHQCQBVA+e1wwdAP4qLk4/WhNghLy1ql9o6Jladb+NCpPMAkUJ
5BVkQ7NQBLg4BGdqXQ4SCisGAQQBl1UBBQEBB0AVE0Dqu6r5Cn3ahWK4IXQtBo0a
QWgdfhUu779zBCyjLgMBCAeIeAQYFgoAIBYhBMDC3NihB0bkfHWxgZZ2cvhFREO4
BQJnal0OAhsMAAoJEJZ2cvhFREO42UgBAP2hw1hELhVWEv4K91fy7rlP6mXZ+Q3a
pXurN2g4kMGfAPwJz24Hsjj4E2HtucwRn8h2uV9oqgAdgwjVPY8/mdz8Ag==
=3g4k
-----END PGP PUBLIC KEY BLOCK-----`

	// Decode the armored data
	publicKey, err := armoredToBytes(armoredPublicKey)
	if err != nil {
		panic(err)
	}

	armoredSignature := `-----BEGIN PGP SIGNATURE-----

iHUEABYKAB0WIQTAwtzYoQdG5Hx1sYGWdnL4RURDuAUCZ26QKQAKCRCWdnL4RURD
uORLAP0ennRcIDSXd31CoyuvdxNIxnPQ9twPUDZAUhW8PCHddQD/fnivGxxx6MhQ
rQBrFXynpYH4vCYsN3s/7qh+4RWpjw4=
=/lHf
-----END PGP SIGNATURE-----`

	signature, err := armoredToBytes(armoredSignature)
	if err != nil {
		panic(err)
	}

	// Perform abi.encodePacked operation
	encoded, err := abiEncodePacked(message, publicKey, signature)
	if err != nil {
		fmt.Printf("Error encoding data: %v\n", err)
		return
	}

	// Test against `Run`
	contract := &gpgEd25519Verify{}
	result, err := contract.Run(encoded)
	if err != nil {
		fmt.Printf("Verification failed: %v\n", err)
		return
	}

	if len(result) > 0 && result[0] == 1 {
		fmt.Println("Signature verification: Success")
	} else {
		fmt.Println("Signature verification: Failed")
	}
}

func abiEncodePacked(message, publicKey, signature []byte) ([]byte, error) {
	toBytes32 := func(length int) []byte {
		padded := make([]byte, 32)
		big.NewInt(int64(length)).FillBytes(padded)
		return padded
	}

	var buffer bytes.Buffer
	buffer.Write(message)
	buffer.Write(toBytes32(len(publicKey)))
	buffer.Write(publicKey)
	buffer.Write(toBytes32(len(signature)))
	buffer.Write(signature)

	// Convert the result to a hexadecimal string for debugging
	result := buffer.Bytes()
	fmt.Printf("Encoded result (hex): %s\n", hex.EncodeToString(result))

	return result, nil
}

func armoredToBytes(armoredData string) ([]byte, error) {
	block, err := armor.Decode(bytes.NewReader([]byte(armoredData)))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(block.Body)
}

var GpgEd25519VerifyGas uint64 = 2000 // GPG Ed25519 signature verification gas price

// gpgEd25519Verify implements native verification for ed25519 signatures produced via gpg
type gpgEd25519Verify struct{}

var (
	errInputTooShort    = errors.New("input too short")
	errInvalidPublicKey   = errors.New("invalid public key")
)

// RequiredGas returns the gas required to execute the pre-compiled contract
func (c *gpgEd25519Verify) RequiredGas(input []byte) uint64 {
	// You can adjust this value based on your needs
	return GpgEd25519VerifyGas
}

// Run performs ed25519 signature verification
func (c *gpgEd25519Verify) Run(input []byte) ([]byte, error) {
	// Input should be: message (32 bytes) || pubkey_len (32 bytes) || pubkey || sig_len (32 bytes) || signature

	// Extract message
	msgLen := 32
	if len(input) < msgLen {
		return nil, errInputTooShort
	}

	message := input[:msgLen]
	messageObj := pgpcrypto.NewPlainMessage(message)

	// Extract public key length and public key
	offset := msgLen
	if len(input) < offset + 32 {
		return nil, errInputTooShort
	}
	
	pubKeyLen := int(new(big.Int).SetBytes(input[offset : offset+32]).Uint64())
	if len(input) < int(offset+32+pubKeyLen) {
		return nil, errInputTooShort
	}
	pubKey := input[offset+32 : offset+32+pubKeyLen]

	// Create public key object
	pubKeyObj, err := pgpcrypto.NewKey(pubKey)
	if err != nil {
		return nil, errInvalidPublicKey
	}

	// Create public keyring
	pubKeyRing, err := pgpcrypto.NewKeyRing(pubKeyObj)
	if err != nil {
		return nil, errInvalidPublicKey
	}

	// Extract signature length and signature
	offset = offset + 32 + pubKeyLen
	if len(input) < offset + 32 {
		return nil, errInputTooShort
	}

	sigLen := int(new(big.Int).SetBytes(input[offset : offset+32]).Uint64())
	if len(input) < int(offset+32+sigLen) {
		return nil, errInputTooShort
	}
	signature := input[offset+32 : offset+32+sigLen]

	// Create signature object
	signatureObj := pgpcrypto.NewPGPSignature(signature)

	// Verify signature
	err = pubKeyRing.VerifyDetached(messageObj, signatureObj, 0)
	if err != nil {
		// Return 32 bytes: 0 for failure
		return []byte{0}, nil
	}

	// Return 32 bytes: 1 for success, 0 for failure
	return []byte{1}, nil
}
