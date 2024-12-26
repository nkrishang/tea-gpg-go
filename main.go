package main

import (
	"encoding/hex"
	"fmt"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

func verifySignature(messageHex, publicKey, signature string) (bool, error) {
	// Decode the hex message
	message, err := hex.DecodeString(messageHex)
	if err != nil {
		return false, fmt.Errorf("failed to decode hex message: %v", err)
	}

	// Create public key object
	pubKeyObj, err := crypto.NewKeyFromArmored(publicKey)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %v", err)
	}

	// Create public keyring
	pubKeyRing, err := crypto.NewKeyRing(pubKeyObj)
	if err != nil {
		return false, fmt.Errorf("failed to create public keyring: %v", err)
	}

	// Parse the armored signature
	signature_obj, err := crypto.NewPGPSignatureFromArmored(signature)
	if err != nil {
		return false, fmt.Errorf("failed to parse signature: %v", err)
	}

	// Create message object
	messageObj := crypto.NewPlainMessage(message)

	// Verify signature
	err = pubKeyRing.VerifyDetached(messageObj, signature_obj, crypto.GetUnixTime())
	if err != nil {
		return false, fmt.Errorf("signature verification failed: %v", err)
	}

	return true, nil
}

func main() {
	messageHex := "48656c6c6f2c20576f726c64" // "Hello, World" in hex
	signature := `-----BEGIN PGP SIGNATURE-----

iHUEABYKAB0WIQTAwtzYoQdG5Hx1sYGWdnL4RURDuAUCZ2qakAAKCRCWdnL4RURD
uE0HAP9B1Mgdl16JTc2FGUONgEZltmx49iJlJw9yuaEIuQtwFAEA7F6tZzrPZ76o
ympT95CfHN2ydyMsHpBHUQ2pDkJOJg8=
=/i/M
-----END PGP SIGNATURE-----`;

	publicKey := `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
-----END PGP PUBLIC KEY BLOCK-----`;

	isVerified, err := verifySignature(messageHex, publicKey, signature)
	if err != nil {
		fmt.Printf("Verification error: %v\n", err)
		return
	}

	if isVerified {
		fmt.Println("Signature verification: Success")
	} else {
		fmt.Println("Signature verification: Failed")
	}
}