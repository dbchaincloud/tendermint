package algo

import (
	"github.com/dbchaincloud/tendermint/crypto"
	"github.com/dbchaincloud/tendermint/crypto/ed25519"
	"github.com/dbchaincloud/tendermint/crypto/sm2"
)

const (
	ED25519 = "ed25519"
	SM2     = "sm2"

	PubKeyEd25519 = "ed25519"
	PubKeySm2     = "sm2"
)

var Algo = SM2

func GetPubKeyType() string {
	switch Algo {
	case ED25519:
		return PubKeyEd25519

	case SM2:
		return PubKeySm2

	default:
		return PubKeyEd25519
	}
}

func GetPrivKeyBytes(privKey crypto.PrivKey) []byte {
	switch Algo {
	case ED25519:
		key := privKey.(ed25519.PrivKeyEd25519)
		return key[:]

	case SM2:
		key := privKey.(sm2.PrivKeySm2)
		return key[:]

	default:
		key := privKey.(ed25519.PrivKeyEd25519)
		return key[:]
	}
}

func GetPubKeyBytes(pubKey crypto.PubKey) []byte {
	switch Algo {
	case ED25519:
		key := pubKey.(ed25519.PubKeyEd25519)
		return key[:]

	case SM2:
		key := pubKey.(sm2.PubKeySm2)
		return key[:]

	default:
		key := pubKey.(ed25519.PubKeyEd25519)
		return key[:]
	}
}

func GetPubKeyFromData(keyType string, keyData []byte) crypto.PubKey {
	switch Algo {
	case ED25519:
		pubkey := ed25519.PubKeyEd25519{}
		copy(pubkey[:], keyData)
		return pubkey

	case SM2:
		pubkey := sm2.PubKeySm2{}
		copy(pubkey[:], keyData)
		return pubkey

	default:
		pubkey := ed25519.PubKeyEd25519{}
		copy(pubkey[:], keyData)
		return pubkey
	}
}

func GenPrivKey() crypto.PrivKey {
	switch Algo {
	case ED25519:
		return ed25519.GenPrivKey()

	case SM2:
		return sm2.GenPrivKey()

	default:
		return ed25519.GenPrivKey()
	}
}

func GenPrivKeyFromSecret(secret []byte) crypto.PrivKey {
	switch Algo {
	case ED25519:
		return ed25519.GenPrivKeyFromSecret(secret)

	case SM2:
		return sm2.GenPrivKeySm2FromSecret(secret)

	default:
		return ed25519.GenPrivKeyFromSecret(secret)
	}
}

func GetPrivKeySize() int {
	switch Algo {
	case ED25519:
		return 64

	case SM2:
		return sm2.PrivKeySize

	default:
		return 64
	}
}

func GetPubKeySize() int {
	switch Algo {
	case ED25519:
		return ed25519.PubKeyEd25519Size

	case SM2:
		return sm2.PubKeySize

	default:
		return ed25519.PubKeyEd25519Size
	}
}

func GetSignatureSize() int {
	switch Algo {
	case ED25519:
		return ed25519.SignatureSize

	case SM2:
		return sm2.SignatureSize

	default:
		return ed25519.SignatureSize
	}
}
