// This package is used to test the dlc scheme package
// small goal of this package is to test the dlc scheme package
// 1. Read about Signature Adaptor, ref: https://bitcoinops.org/en/topics/adaptor-signatures/
// 2. Code the adaptor signature

package main

import (
	"crypto/sha256"
	"log"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
	"github.com/stretchr/testify/assert"
)

// Test_Adaptor_Signature tests the adaptor signature, ref: https://bitcoinops.org/en/topics/adaptor-signatures/
// Test the basic scheme of the adaptor signature using basic swap token between two parties Alice and Bob. Alice swap 1 BTC with Bob for 1000 USDT
// 1. Alice create a Adaptor Signature for the swap. She tweaks the signature with a secret value t, and send the tweaked signature to Bob (Adaptor Signature)
// 2. Bob verifies the Adaptor and if it is correct. He create his own Adaptor base on the Alice's Adaptor, this Adaptor is valid to claim the 1000 USDT
// 3. When Alice claim the 1000 USDT, she will reveal the secret t to Bob, and Bob can verify the secret t with the Adaptor to claim the 1 BTC
func Test_Adaptor_Signature2(t *testing.T) {
	s := testhelper.TestSuite{}
	s.SetupStaticSimNetSuite(t, log.Default())

	alicePair, alicePoint := s.GetKeypairWithEvenY(ALICE_WALLET_SEED)
	bobPair, bobPoint := s.GetKeypairWithEvenY(BOB_WALLET_SEED)

	// 1. Alice create a Adaptor Signature for the swap. She tweaks the signature with a secret value t, and send the tweaked signature to Bob (Adaptor Signature)
	T, tPoint := s.GetKeypairWithEvenY("") // T = tG
	R, rPoint := s.GetKeypairWithEvenY("") // R = rG nonce

	tx1 := sha256.Sum256([]byte("Alice send 1 BTC to Bob"))
	tx2 := sha256.Sum256([]byte("Bob send 1000 USDT to Alice"))

	// aggrPoint = R + T = rPoint + tPoint
	var aggrPoint btcec.JacobianPoint
	btcec.AddNonConst(&rPoint, &tPoint, &aggrPoint)
	aggrPoint.ToAffine()
	for aggrPoint.Y.IsOdd() {
		log.Printf("AggrPoint.Y is odd\n")
		T, tPoint = s.GetKeypairWithEvenY("") // T = tG
		R, rPoint = s.GetKeypairWithEvenY("") // R = rG nonce
		btcec.AddNonConst(&rPoint, &tPoint, &aggrPoint)
		aggrPoint.ToAffine()
	}

	// commitment = tagged_hash("BIP0340/challenge", (R + T)_x | P_x | tx1)
	commitment := chainhash.TaggedHash(chainhash.TagBIP0340Challenge, aggrPoint.X.Bytes()[:], alicePoint.X.Bytes()[:], tx1[:])

	var e btcec.ModNScalar
	ok := e.SetBytes((*[32]byte)(commitment))
	assert.Equal(s.T, ok, uint32(0), "commitment is overflow")

	// tweakS = s' = r + e*AlicePriv
	tweakS := new(btcec.ModNScalar).Mul2(&e, &alicePair.GetTestPriv().Key).Add(&R.GetTestPriv().Key)

	// --> Alice's Adaptor is (R, T, s'), ALice send this value to Bob

	// 2.1 Bob verifies the Adaptor and if it is correct. s'G ?= R + e*AlicePub
	var result, right, left btcec.JacobianPoint
	btcec.ScalarMultNonConst(&e, &alicePoint, &result) // e * AlicePub
	result.ToAffine()
	btcec.AddNonConst(&rPoint, &result, &right) // R + e*AlicePub = right
	right.ToAffine()

	btcec.ScalarBaseMultNonConst(tweakS, &left) // s'G = left
	left.ToAffine()

	assert.Equal(s.T, left, right) // left ?= right

	// 2.2 Bob create his own
	bobRPair, bobRPoint := s.GetKeypairWithEvenY("") // R' = r'G nonce

	var BobAggrPoint btcec.JacobianPoint
	btcec.AddNonConst(&bobRPoint, &tPoint, &BobAggrPoint)
	BobAggrPoint.ToAffine()

	// get bobRPoint --> BobAggrPoint.Y is even
	for BobAggrPoint.Y.IsOdd() || bobRPoint.Y.IsOdd() {
		log.Print("BobAggrPoint.Y is odd\n")
		bobRPair, bobRPoint = s.GetKeypairWithEvenY("")
		btcec.AddNonConst(&bobRPoint, &tPoint, &BobAggrPoint)
		BobAggrPoint.ToAffine()
	}
	if BobAggrPoint.Y.IsOdd() {
		log.Printf("BobAggrPoint.Y is odd, hi vong khong vao day 2 lan because the T is netigate 2 times\n")
	}

	// commitment = tagged_hash("BIP0340/challenge", R'_x + T_x | P_x | tx2)
	commitment = chainhash.TaggedHash(chainhash.TagBIP0340Challenge, BobAggrPoint.X.Bytes()[:], bobPoint.X.Bytes()[:], tx2[:])

	var bobE btcec.ModNScalar
	ok = bobE.SetBytes((*[32]byte)(commitment))
	assert.Equal(s.T, ok, uint32(0), "commitment is overflow")

	// sBob = r' + e * p sinature of Bob
	sBob := new(btcec.ModNScalar).Mul2(&bobE, &bobPair.GetTestPriv().Key).Add(&bobRPair.GetTestPriv().Key)

	// --> Bob's Adaptor is (R', T, sBob), Bob send this value to Alice

	// 3.1 Alice using Bob's Adaptor to claim the 1000 USDT
	sign := sBob.Add(&T.GetTestPriv().Key)
	signature := schnorr.NewSignature(&BobAggrPoint.X, sign)

	oke := signature.Verify(tx2[:], bobPair.Pub)

	assert.Equal(s.T, oke, true)

	// 3.2 Bob get the Alice Signature and get the secrete t
	// sBobNegate = -sBob
	sBobNegate := new(btcec.ModNScalar).Mul2(&bobE, &bobPair.GetTestPriv().Key).Add(&bobRPair.GetTestPriv().Key).Negate()
	secrete := sign.Add(sBobNegate)
	assert.Equal(t, secrete.Equals(&T.GetTestPriv().Key), true)

	// 3.3 Bob using Alice Transaction
	aliceSign := tweakS.Add(secrete)

	aliceSignature := schnorr.NewSignature(&aggrPoint.X, aliceSign)
	oke = aliceSignature.Verify(tx1[:], alicePair.Pub)
	assert.Equal(s.T, oke, true)
}
