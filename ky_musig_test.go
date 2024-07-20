// This file is use to test all about the schnorr signature
package main

import (
	"crypto/sha256"
	"testing"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
)

// This test is to verify that the schnorr signature is correct by using the format
// go test -timeout 30s -run ^TestSingleSchnorrByFormat$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestSingleSchnorrByFormat(t *testing.T) {
	s := TestSuite{}
	s.setupStaticSimNetSuite(t)

	// Create a key pair for Alice
	_, aliceKeyPair := s.newKeyPair(ALICE_WALLET_SEED)
	_, nonce := s.newKeyPair("")

	var alice_pub_point btcec.JacobianPoint
	var nonce_point btcec.JacobianPoint

	aliceKeyPair.pub.AsJacobian(&alice_pub_point)
	nonce.pub.AsJacobian(&nonce_point)

	if nonce_point.Y.IsOdd() {
		nonce_point.Y.Negate(1)
		nonce_point.Y.Normalize()
		nonce.priv.Key.Negate()
	}

	if alice_pub_point.Y.IsOdd() {
		alice_pub_point.Y.Negate(1)
		alice_pub_point.Y.Normalize()
		aliceKeyPair.priv.Key.Negate()
	}

	// Create a message to sign
	msg := []byte("alice transaction")
	// hash the message
	hash := sha256.Sum256(msg)

	// create Charllenge = tagged_hash("BIP0340/challenge", R_x|P_x|msg)
	challenge := chainhash.TaggedHash(chainhash.TagBIP0340Challenge, nonce_point.X.Bytes()[:], alice_pub_point.X.Bytes()[:], hash[:])
	var e btcec.ModNScalar
	overflow := e.SetBytes((*[32]byte)(challenge))
	assert.Equal(s.t, overflow, uint32(0), "overflow")

	// create s = k + challenge * priv
	sign := new(btcec.ModNScalar).Mul2(&e, &aliceKeyPair.priv.Key).Add(&nonce.priv.Key)

	schnorrSig := schnorr.NewSignature(&nonce_point.X, sign)
	ok := schnorrSig.Verify(hash[:], aliceKeyPair.pub)
	assert.True(t, ok)
}

// This test is to verify that the schnorr signature is correct by using the library
// go test -timeout 30s -run ^TestSingleSchnorr$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestSingleSchnorr(t *testing.T) {
	s := TestSuite{}
	s.setupStaticSimNetSuite(t)

	// Create a key pair for Alice
	_, aliceKeyPair := s.newKeyPair(ALICE_WALLET_SEED)

	// Generate a nonce
	Nonce, err := musig2.GenNonces(musig2.WithPublicKey(aliceKeyPair.pub))
	assert.Nil(t, err)

	// Create a message to sign
	msg := []byte("alice transaction")

	// hash the message
	hash := sha256.Sum256(msg)

	// Sign the message
	signature, _ := musig2.Sign(Nonce.SecNonce, aliceKeyPair.priv, Nonce.PubNonce, []*secp256k1.PublicKey{aliceKeyPair.pub}, hash)

	// Verify the signature
	ok := signature.Verify(Nonce.PubNonce, Nonce.PubNonce, []*secp256k1.PublicKey{aliceKeyPair.pub}, aliceKeyPair.pub, hash)
	assert.True(t, ok)
}

func TestMultiSchorrByFormat(t *testing.T) {
	s := TestSuite{}
	s.setupStaticSimNetSuite(t)

	// Create a key pair for Alice
	_, aliceKeyPair := s.newKeyPair(ALICE_WALLET_SEED)

	// Create a key pair for Bob
	_, bobKeyPair := s.newKeyPair(BOB_WALLET_SEED)

	// Generate a nonce
	_, aliceNonce := s.newKeyPair("")
	_, bobNonce := s.newKeyPair("")

	var alice_pub_point btcec.JacobianPoint
	var bob_pub_point btcec.JacobianPoint
	var alice_nonce_point btcec.JacobianPoint
	var bob_nonce_point btcec.JacobianPoint

	aliceKeyPair.pub.AsJacobian(&alice_pub_point)
	bobKeyPair.pub.AsJacobian(&bob_pub_point)
	aliceNonce.pub.AsJacobian(&alice_nonce_point)
	bobNonce.pub.AsJacobian(&bob_nonce_point)

	var pubkeyAgrr btcec.JacobianPoint
	btcec.AddNonConst(&alice_pub_point, &bob_pub_point, &pubkeyAgrr)
	var nonceAgrr btcec.JacobianPoint
	btcec.AddNonConst(&alice_nonce_point, &bob_nonce_point, &nonceAgrr)

	// verify the y coordinate of the aggregated public key
	if pubkeyAgrr.Y.IsOdd() {
		pubkeyAgrr.Y.Negate(1)
		pubkeyAgrr.Y.Normalize()
		aliceKeyPair.priv.Key.Negate()
		bobKeyPair.priv.Key.Negate()
	}

	if nonceAgrr.Y.IsOdd() {
		nonceAgrr.Y.Negate(1)
		nonceAgrr.Y.Normalize()
		aliceNonce.priv.Key.Negate()
		bobNonce.priv.Key.Negate()
	}

	// Create a message to sign
	msg := []byte("alice and bob transaction")
	// hash the message
	hash := sha256.Sum256(msg)

	// create Charllenge = tagged_hash("BIP0340/challenge", R_x|P_x|msg)
	challenge := chainhash.TaggedHash(chainhash.TagBIP0340Challenge, nonceAgrr.X.Bytes()[:], pubkeyAgrr.X.Bytes()[:], hash[:])
	var e btcec.ModNScalar
	overflow := e.SetBytes((*[32]byte)(challenge))
	assert.Equal(s.t, overflow, uint32(0), "overflow")

	aliceSign := new(btcec.ModNScalar).Mul2(&e, &aliceKeyPair.priv.Key).Add(&aliceNonce.priv.Key)
	bobSign := new(btcec.ModNScalar).Mul2(&e, &bobKeyPair.priv.Key).Add(&bobNonce.priv.Key)

	sign := new(btcec.ModNScalar).Add(aliceSign).Add(bobSign)

	schnorrSig := schnorr.NewSignature(&nonceAgrr.X, sign)
	ok := schnorrSig.Verify(hash[:], btcec.NewPublicKey(&pubkeyAgrr.X, &pubkeyAgrr.Y))
	assert.True(t, ok)
}

// func test 2-2 multisig by using library
// go test -timeout 30s -run ^TestMultiSchnorr$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestMultiSigSchnorr(t *testing.T) {
	s := TestSuite{}
	s.setupStaticSimNetSuite(t)

	// Create a key pair for Alice
	_, aliceKeyPair := s.newKeyPair(ALICE_WALLET_SEED)

	// Create a key pair for Bob
	_, bobKeyPair := s.newKeyPair(BOB_WALLET_SEED)

	// Generate a nonce
	aliceNonce, err := musig2.GenNonces(musig2.WithPublicKey(aliceKeyPair.pub))
	assert.Nil(t, err)

	bobNonce, err := musig2.GenNonces(musig2.WithPublicKey(bobKeyPair.pub))
	assert.Nil(t, err)

	// Create a message to sign
	msg := []byte("alice transaction")
	// hash the message
	hash := sha256.Sum256(msg)

	// aggregate the nonce
	aggrNonce, err := musig2.AggregateNonces([][66]byte{aliceNonce.PubNonce, bobNonce.PubNonce})
	assert.Nil(t, err)

	// aggregate the public key
	aggrPubKey, _, _, err := musig2.AggregateKeys([]*secp256k1.PublicKey{aliceKeyPair.pub, bobKeyPair.pub}, false)
	assert.Nil(t, err)

	aliceSign, err := musig2.Sign(aliceNonce.SecNonce, aliceKeyPair.priv, aggrNonce, []*secp256k1.PublicKey{aliceKeyPair.pub, bobKeyPair.pub}, hash)
	assert.Nil(t, err)

	bobSign, err := musig2.Sign(bobNonce.SecNonce, bobKeyPair.priv, aggrNonce, []*secp256k1.PublicKey{aliceKeyPair.pub, bobKeyPair.pub}, hash)
	assert.Nil(t, err)

	// aggregate the signature

	finalSign := musig2.CombineSigs(aliceSign.R, []*musig2.PartialSignature{aliceSign, bobSign})
	ok := finalSign.Verify(hash[:], aggrPubKey.FinalKey)
	assert.True(t, ok)
}
