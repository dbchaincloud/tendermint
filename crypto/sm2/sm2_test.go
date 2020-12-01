package sm2_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/sm2"
)
//
//// nolint
//func TestSignAndValidate(t *testing.T) {
//	for i := 0; i < 1000; i++ {
//		privKey := sm2.GenPrivKey()
//		pubKey := privKey.PubKey()
//
//		msg := crypto.CRandBytes(128)
//		sig, err := privKey.Sign(msg)
//		require.Nil(t, err)
//
//		// Test the signature
//		if !pubKey.VerifySignature(msg, sig) {
//			fmt.Printf("# %d: Verify error\n", i)
//		}
//
//		// Mutate the signature, just one bit.
//		sig[7] ^= byte(0x01)
//
//		assert.False(t, pubKey.VerifySignature(msg, sig))
//	}
//
//}
//
//func TestSm2SignAndSm2Validate(t *testing.T) {
//	for i := 0; i < 1000; i++ {
//		privKey := sm2.GenPrivKey()
//		pubKey := privKey.PubKey().(sm2.PubKeySm2)
//
//		msg := crypto.CRandBytes(128)
//		sig, err := privKey.Sm2Sign(msg)
//		require.Nil(t, err)
//
//		// Test the signature
//		if !pubKey.Sm2VerifyBytes(msg, sig) {
//			fmt.Printf("# %d: Verify error\n", i)
//		}
//
//		// Mutate the signature, just one bit.
//		sig[7] ^= byte(0x01)
//
//		assert.False(t, pubKey.VerifySignature(msg, sig))
//	}
//
//}
//
//func TestGenPrivKeySm2FromSecret(t *testing.T) {
//	a := sm2.GenPrivKeySm2FromSecret([]byte("mySecret1"))
//	b := sm2.GenPrivKeySm2FromSecret([]byte("mySecret1"))
//	c := sm2.GenPrivKeySm2FromSecret([]byte("mySecret2"))
//
//	require.Equal(t, a, b)
//	require.NotEqual(t, a, c)
//}


func TestSignAndValidateEd25519(t *testing.T) {

	privKey := sm2.GenPrivKey()
	pubKey := privKey.PubKey()
	//fmt.Println("pubKey\t",pubKey)

	msg := crypto.CRandBytes(128)
	sig, err := privKey.Sign(msg)
	require.Nil(t, err)

	// Test the signature
	assert.True(t, pubKey.VerifyBytes(msg, sig))

	// Mutate the signature, just one bit.
	// TODO: Replace this with a much better fuzzer, tendermint/ed25519/issues/10
	sig[7] ^= byte(0x01)

	assert.False(t, pubKey.VerifyBytes(msg, sig))
}
