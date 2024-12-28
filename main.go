package main

import (
	"bytes"
	"io"

	"encoding/hex"
	"errors"
	"fmt"

	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"golang.org/x/crypto/openpgp/armor"
)

func main() {
	messageHex := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
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

iHUEABYKAB0WIQTAwtzYoQdG5Hx1sYGWdnL4RURDuAUCZ26cUgAKCRCWdnL4RURD
uMEAAP4izV1v1FOyutRmQbxB/7PP+oNKLHTaUX6PtkThYx0jtQEAgo7kCZSMHqhw
0hksOnbL60ZVZFTyDRMvUt/oNd+5rQQ=
=/V6w
-----END PGP SIGNATURE-----`

	signature, err := armoredToBytes(armoredSignature)
	if err != nil {
		panic(err)
	}

	// Perform abi.encodePacked operation
	encoded, err := abiEncode(message, publicKey, signature)
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

func abiEncode(message, publicKey, signature []byte) ([]byte, error) {
	// Ensure the message is exactly 32 bytes
	if len(message) != 32 {
		return nil, fmt.Errorf("message must be 32 bytes")
	}
	var messageFixed [32]byte
	copy(messageFixed[:], message)

	// Define ABI types
	bytesType, err := abi.NewType("bytes", "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create bytes type: %v", err)
	}
	bytes32Type, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create bytes32 type: %v", err)
	}

	// Create ABI arguments
	arguments := abi.Arguments{
		{Type: bytes32Type},
		{Type: bytesType},
		{Type: bytesType},
	}

	// Pack the data
	result, err := arguments.Pack(messageFixed, publicKey, signature)
	if err != nil {
		return nil, fmt.Errorf("failed to pack data: %v", err)
	}

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
	errDecodingFailed    = errors.New("failed to decode input")
	errInvalidPublicKey   = errors.New("invalid public key")
)

// RequiredGas returns the gas required to execute the pre-compiled contract
func (c *gpgEd25519Verify) RequiredGas(input []byte) uint64 {
	// You can adjust this value based on your needs
	return GpgEd25519VerifyGas
}

// Run performs ed25519 signature verification
func (c *gpgEd25519Verify) Run(input []byte) ([]byte, error) {
	// Input should be: abi.encode(bytes32 message, bytes publicKey, bytes signature)
	
	decode := func(encodedInput []byte) ([32]byte, []byte, []byte, error) {
		// Define ABI types
		bytesType, err := abi.NewType("bytes", "", nil)
		if err != nil {
			return [32]byte{}, nil, nil, fmt.Errorf("failed to create bytes type: %v", err)
		}
		bytes32Type, err := abi.NewType("bytes32", "", nil)
		if err != nil {
			return [32]byte{}, nil, nil, fmt.Errorf("failed to create bytes32 type: %v", err)
		}

		// Create ABI arguments
		arguments := abi.Arguments{
			{Type: bytes32Type},
			{Type: bytesType},
			{Type: bytesType},
		}

		// Unpack the encoded data
		unpacked, err := arguments.Unpack(encodedInput)
		if err != nil {
			return [32]byte{}, nil, nil, fmt.Errorf("failed to unpack data: %v", err)
		}

		// Ensure we have the correct number of elements
		if len(unpacked) != 3 {
			return [32]byte{}, nil, nil, fmt.Errorf("unexpected number of decoded arguments: got %d, want 3", len(unpacked))
		}

		// Extract each value
		message, ok := unpacked[0].([32]byte)
		if !ok {
			return [32]byte{}, nil, nil, fmt.Errorf("failed to cast message to [32]byte")
		}
		publicKey, ok := unpacked[1].([]byte)
		if !ok {
			return [32]byte{}, nil, nil, fmt.Errorf("failed to cast publicKey to []byte")
		}
		signature, ok := unpacked[2].([]byte)
		if !ok {
			return [32]byte{}, nil, nil, fmt.Errorf("failed to cast signature to []byte")
		}

		return message, publicKey, signature, nil
	}

	message, pubKey, signature, err := decode(input)
	if err != nil {
		return nil, errDecodingFailed
	}

	// Create message object
	messageObj := pgpcrypto.NewPlainMessage(message[:])

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
