package encoding

import (
	"errors"
	"fmt"
	"github.com/dbchaincloud/tendermint/crypto/sm2"

	"github.com/dbchaincloud/tendermint/crypto"
	"github.com/dbchaincloud/tendermint/crypto/ed25519"
	pc "github.com/dbchaincloud/tendermint/proto/crypto/keys"
)

// PubKeyToProto takes crypto.PubKey and transforms it to a protobuf Pubkey
func PubKeyToProto(k crypto.PubKey) (pc.PublicKey, error) {
	if k == nil {
		return pc.PublicKey{}, errors.New("nil PublicKey")
	}
	var kp pc.PublicKey
	switch k := k.(type) {
	case ed25519.PubKeyEd25519:
		kp = pc.PublicKey{
			Sum: &pc.PublicKey_Ed25519{
				Ed25519: k[:],
			},
		}
	case sm2.PubKeySm2:
		kp = pc.PublicKey{
			Sum: &pc.PublicKey_Sm2{
				Sm2: k[:],
			},
		}
	default:
		return kp, fmt.Errorf("toproto: key type %v is not supported", k)
	}
	return kp, nil
}

// PubKeyFromProto takes a protobuf Pubkey and transforms it to a crypto.Pubkey
func PubKeyFromProto(k *pc.PublicKey) (crypto.PubKey, error) {
	if k == nil {
		return nil, errors.New("nil PublicKey")
	}
	switch k := k.Sum.(type) {
	case *pc.PublicKey_Ed25519:
		if len(k.Ed25519) != ed25519.PubKeyEd25519Size {
			return nil, fmt.Errorf("invalid size for PubKeyEd25519. Got %d, expected %d",
				len(k.Ed25519), ed25519.PubKeyEd25519Size)
		}
		var pk ed25519.PubKeyEd25519
		copy(pk[:], k.Ed25519)
		return pk, nil

	case *pc.PublicKey_Sm2:
		if len(k.Sm2) != sm2.PubKeySize {
			return nil, fmt.Errorf("invalid size for PubKeyEd25519. Got %d, expected %d",
				len(k.Sm2), sm2.PubKeySize)
		}
		var pk sm2.PubKeySm2
		copy(pk[:], k.Sm2)
		return pk, nil
	default:
		return nil, fmt.Errorf("fromproto: key type %v is not supported", k)
	}
}

// PrivKeyToProto takes crypto.PrivKey and transforms it to a protobuf PrivKey
func PrivKeyToProto(k crypto.PrivKey) (pc.PrivateKey, error) {
	var kp pc.PrivateKey
	switch k := k.(type) {
	case ed25519.PrivKeyEd25519:
		kp = pc.PrivateKey{
			Sum: &pc.PrivateKey_Ed25519{
				Ed25519: k[:],
			},
		}

	case sm2.PrivKeySm2:
		kp = pc.PrivateKey{
			Sum: &pc.PrivateKey_Sm2{
				Sm2: k[:],
			},
		}
	default:
		return kp, errors.New("toproto: key type is not supported")
	}
	return kp, nil
}

// PrivKeyFromProto takes a protobuf PrivateKey and transforms it to a crypto.PrivKey
func PrivKeyFromProto(k pc.PrivateKey) (crypto.PrivKey, error) {
	switch k := k.Sum.(type) {
	case *pc.PrivateKey_Ed25519:

		if len(k.Ed25519) != ed25519.PubKeyEd25519Size {
			return nil, fmt.Errorf("invalid size for PubKeyEd25519. Got %d, expected %d",
				len(k.Ed25519), ed25519.PubKeyEd25519Size)
		}
		var pk ed25519.PrivKeyEd25519
		copy(pk[:], k.Ed25519)
		return pk, nil

	case *pc.PrivateKey_Sm2:

		if len(k.Sm2) != sm2.PrivKeySize {
			return nil, fmt.Errorf("invalid size for PubKeyEd25519. Got %d, expected %d",
				len(k.Sm2), sm2.PrivKeySize )
		}
		var pk sm2.PrivKeySm2
		copy(pk[:], k.Sm2)
		return pk, nil
	default:
		return nil, errors.New("fromproto: key type not supported")
	}
}
