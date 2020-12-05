package v0

import (
	amino "github.com/tendermint/go-amino"

	"github.com/dbchaincloud/tendermint/types"
)

var cdc = amino.NewCodec()

func init() {
	RegisterBlockchainMessages(cdc)
	types.RegisterBlockAmino(cdc)
}
