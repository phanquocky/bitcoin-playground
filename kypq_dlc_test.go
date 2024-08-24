// This package is for testing the DLC (Discreet Log Contract) implementation.
// ref:
// 1. https://bitcoinops.org/en/topics/discreet-log-contracts/
// 2. https://adiabat.github.io/dlc.pdf (original paper)
// 3. https://github.com/aljazceru/discreet-log-contracts (github resource)
// 4. https://livestream.com/accounts/2261474/events/9019383/videos/202643580 (video MIT Bitcoin Expo 2020)

// TODO:
// 1. Read about DLC and understand the concept
// 2. Code POC the DLC
// 3. Document
package main

import (
	"crypto/sha256"
	"log"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
	"github.com/stretchr/testify/assert"
)

// This Test_DLC is for testing the DLC implementation
// The context:
// 1. Alice and Bob are the two parties
// 2. Olivia is the oracle

// Alice and Bob want to create the contract if Tomorow is a rainy day, Alice will pay Bob 1 BTC, otherwise Bob will pay Alice 1 BTC.
// Olivia is the oracle who will provide the weather information.

// Steps:
// 1. Contract creatation: Alice and Bob create the contract each other.
// 2. CET (Contract Execution Transaction): Alice and Bob create the CET with the oracle signature.
// 3. Oracle signing: Tomorow Signumber with Precommit R value.
// 4. Contract Execution: Alice and Bob execute the contract.
func Test_DLC(t *testing.T) {
	s := testhelper.TestSuite{}
	s.SetupStaticSimNetSuite(t, log.Default())

	// Oracle setup
	oliviaPair, oliviaPoint := s.GetKeypairWithEvenY(OLIVIA_WALLET_SEED)
	rPair, rPoint := s.GetKeypairWithEvenY("")

	// 1. Contract creatation
	// Alice and Bob send 1BTC to the multisig address
	alicePair, _ := s.GetKeypairWithEvenY(ALICE_WALLET_SEED)
	bobPair, bobPoint := s.GetKeypairWithEvenY(BOB_WALLET_SEED)

	// Generate a nonce
	aliceNonce, err := musig2.GenNonces(musig2.WithPublicKey(alicePair.Pub))
	assert.Nil(t, err)

	bobNonce, err := musig2.GenNonces(musig2.WithPublicKey(bobPair.Pub))
	assert.Nil(t, err)

	// aggregate the nonce
	aggrNonce, err := musig2.AggregateNonces([][66]byte{aliceNonce.PubNonce, bobNonce.PubNonce})
	assert.Nil(t, err)

	aggrPubKey, _, _, err := musig2.AggregateKeys([]*btcec.PublicKey{alicePair.Pub, bobPair.Pub}, false)
	assert.NoError(t, err)

	p2taprootScript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_1).AddData(schnorr.SerializePubKey(aggrPubKey.FinalKey)).Script() // NewScriptBuilder().AddOp(OP_1).AddData(q).Script()
	assert.Nil(t, err)

	txHash1, err := chainhash.NewHashFromStr("aff48a9b83dc525d330ded64e1b6a9e127c99339f7246e2c89e06cd83493af9b") // this is a Alice Output
	assert.Nil(t, err)

	txHash2, err := chainhash.NewHashFromStr("4f8d9e23cb7b6a8d56e1a9a7b0451dca0df72305fbf3e7b5ac9b8a376f93f1a2") // this is Bob Output
	assert.Nil(t, err)

	tx := wire.NewMsgTx(2)

	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  *txHash1,
			Index: 0,
		}})
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  *txHash2,
			Index: 0,
		}})
	txOut := &wire.TxOut{
		Value: 2000000000, PkScript: p2taprootScript,
	}
	tx.AddTxOut(txOut)

	aliceSig, err := txscript.SignatureScript(tx, 0, []byte{}, txscript.SigHashSingle, alicePair.GetTestPriv(), true)
	assert.Nil(t, err)
	tx.TxIn[0].SignatureScript = aliceSig

	bobSig, err := txscript.SignatureScript(tx, 1, []byte{}, txscript.SigHashSingle, bobPair.GetTestPriv(), true)
	assert.Nil(t, err)
	tx.TxIn[1].SignatureScript = bobSig

	// add the transaction to the blockchain
	blockUtxos := blockchain.NewUtxoViewpoint()
	blockUtxos.AddTxOut(btcutil.NewTx(tx), 0, 0)

	// 2. CET (Contract Execution Transaction)
	// Alice and Bob already create mutisig output it have 2BTC. Now they want to create the set of Transactions respectively with the weather information (Rainy or Cloudy or Sunny)
	// IF rainy, Multisig output will pay to Bob 2BTC
	// IF Cloudy, Multisig output will pay to Alice 1BTC and Bob 1BTC
	// IF Sunny, Multisig output will pay to Alice 2BTC
	// Create 3 pairs of transactions

	// 2.1 Rainy case
	tx_21 := wire.NewMsgTx(2)
	tx_21.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  tx.TxHash(),
			Index: 0,
		}})
	// bobPub21 := bobPoint + si*G , si*G = R - Hash("rainny", R) * V , V = oliviaPoint, R = rPoint
	commitment := sha256.Sum256(append([]byte("rainny"), rPoint.X.Bytes()[:]...))
	var e btcec.ModNScalar
	overflow := e.SetBytes((*[32]byte)(&commitment))
	assert.Equal(s.T, overflow, uint32(0), "overflow commitment")

	e.Negate() // -e = -Hash("rainny", R)
	var result btcec.JacobianPoint
	btcec.ScalarMultNonConst(&e, &oliviaPoint, &result) // -Hash("rainny", R) * V
	result.ToAffine()

	var bobPub21Point btcec.JacobianPoint
	btcec.AddNonConst(&rPoint, &result, &bobPub21Point) // R - Hash("rainny", R) * V
	bobPub21Point.ToAffine()

	btcec.AddNonConst(&bobPoint, &bobPub21Point, &bobPub21Point) // bobPub21Point = bobPublic + si*G = bobPublice + R - Hash("rainny", R) * V
	bobPub21Point.ToAffine()

	bobPub21 := btcec.NewPublicKey(&bobPub21Point.X, &bobPub21Point.Y)
	pkScript21, err := txscript.NewScriptBuilder().AddOp(txscript.OP_1).AddData(schnorr.SerializePubKey(bobPub21)).Script()
	assert.Nil(s.T, err)
	tx_21.AddTxOut(&wire.TxOut{
		Value: 2000000000, PkScript: pkScript21,
	})
	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		tx.TxOut[0].PkScript,
		tx.TxOut[0].Value,
	)
	tx_21SigHash := txscript.NewTxSigHashes(tx_21, inputFetcher)
	signatureHash, err := txscript.CalcTaprootSignatureHash(tx_21SigHash, txscript.SigHashDefault, tx_21, 0, inputFetcher)
	assert.Nil(s.T, err)

	aliceSignature, err := musig2.Sign(aliceNonce.SecNonce, alicePair.GetTestPriv(), aggrNonce, []*secp256k1.PublicKey{alicePair.Pub, bobPair.Pub}, ([32]byte)(signatureHash))
	assert.Nil(t, err)
	// Alice send tx_21 to Bob, Bob will wait for the oracle signature (rainny), and then sign the transaction to claim 2BTC

	// 3. Oracle signing
	// Olivia will sign the message with the precommit R value, and broadcast it to the network
	// 3.1 Case Rainy

	// oliviaSig = r - Hash("rainny", R) * oliviaPriv , e = - Hash("rainny", R)
	oliviaSig := new(btcec.ModNScalar).Mul2(&e, &oliviaPair.GetTestPriv().Key).Add(&rPair.GetTestPriv().Key) // --> Broadcast to the network, to confirm it is a rainy day

	// 4. Contract Execution
	// 4.1 Bob get oliviaSig and reconize that it value is Rainy and claim 2BTC

	bobSignature, err := musig2.Sign(bobNonce.SecNonce, bobPair.GetTestPriv(), aggrNonce, []*secp256k1.PublicKey{alicePair.Pub, bobPair.Pub}, ([32]byte)(signatureHash))
	assert.Nil(t, err)

	fullSignature := musig2.CombineSigs(bobSignature.R, []*musig2.PartialSignature{aliceSignature, bobSignature})

	oke := fullSignature.Verify((signatureHash), aggrPubKey.FinalKey)
	assert.Equal(s.T, oke, true)
	log.Printf("Signature is valid : %v \n", oke)

	tx_21.TxIn[0].Witness = wire.TxWitness{fullSignature.Serialize()}

	sigCache := txscript.NewSigCache(5)
	hashCache := txscript.NewHashCache(5)

	err = blockchain.ValidateTransactionScripts(
		btcutil.NewTx(tx_21), blockUtxos, txscript.StandardVerifyFlags, sigCache, hashCache,
	)
	assert.Nil(s.T, err)

	blockUtxos.AddTxOut(btcutil.NewTx(tx_21), 0, 2)

	// 4.2 Bob claim 2 BTC from tx_21 output
	bobNewPrivateKey := new(btcec.ModNScalar).Add2(&bobPair.GetTestPriv().Key, oliviaSig)
	tx_bob := wire.NewMsgTx(2)
	tx_bob.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  tx_21.TxHash(),
			Index: 0,
		}})
	tx_bob.AddTxOut(&wire.TxOut{
		Value: 2000000000, PkScript: bobPair.Pub.SerializeCompressed(),
	})
	inputFetcher = txscript.NewCannedPrevOutputFetcher(
		tx_21.TxOut[0].PkScript,
		tx_21.TxOut[0].Value,
	)
	tx_bobSigHash := txscript.NewTxSigHashes(tx_bob, inputFetcher)
	signatureHash, err = txscript.CalcTaprootSignatureHash(tx_bobSigHash, txscript.SigHashDefault, tx_bob, 0, inputFetcher)
	assert.Nil(s.T, err)

	bobSign, err := schnorr.Sign(btcec.PrivKeyFromScalar(bobNewPrivateKey), signatureHash)
	assert.Nil(s.T, err)

	oke = bobSign.Verify(signatureHash, bobPub21)
	assert.Equal(s.T, oke, true)

	tx_bob.TxIn[0].Witness = wire.TxWitness{bobSign.Serialize()}

	err = blockchain.ValidateTransactionScripts(
		btcutil.NewTx(tx_bob), blockUtxos, txscript.StandardVerifyFlags, sigCache, hashCache,
	)

	assert.Nil(s.T, err)

	// DONE :)
}
