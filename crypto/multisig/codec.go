package multisig

import (
	amino "github.com/tendermint/go-amino"
	"github.com/dbchaincloud/tendermint/crypto/sm2"

	"github.com/dbchaincloud/tendermint/crypto"
	"github.com/dbchaincloud/tendermint/crypto/ed25519"
	"github.com/dbchaincloud/tendermint/crypto/secp256k1"
	"github.com/dbchaincloud/tendermint/crypto/sr25519"
)

// TODO: Figure out API for others to either add their own pubkey types, or
// to make verify / marshal accept a cdc.
const (
	PubKeyMultisigThresholdAminoRoute = "tendermint/PubKeyMultisigThreshold"
)

var cdc = amino.NewCodec()

func init() {
	cdc.RegisterInterface((*crypto.PubKey)(nil), nil)
	cdc.RegisterConcrete(PubKeyMultisigThreshold{},
		PubKeyMultisigThresholdAminoRoute, nil)
	cdc.RegisterConcrete(ed25519.PubKeyEd25519{},
		ed25519.PubKeyAminoName, nil)
	cdc.RegisterConcrete(sr25519.PubKeySr25519{},
		sr25519.PubKeyAminoName, nil)
	cdc.RegisterConcrete(secp256k1.PubKeySecp256k1{},
		secp256k1.PubKeyAminoName, nil)
	cdc.RegisterConcrete(sm2.PubKeySm2{},
		sm2.PubKeyAminoName, nil)
}
