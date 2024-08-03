// This file is use to test all about the schnorr signature
package main

import (
	"crypto/sha256"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
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

func TestSimpleTaprootTransaction(t *testing.T) {
	s := TestSuite{}
	s.setupStaticSimNetSuite(t)

	_, keypair := s.newKeyPair("")

	rootcommitment := []byte{}
	q := txscript.ComputeTaprootOutputKey(keypair.pub, rootcommitment[:])
	assert.NotNil(t, q)

	taprootAddr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(q), s.btcdChainConfig)
	assert.Nil(t, err)

	p2taprootScript, err := txscript.PayToAddrScript(taprootAddr) // NewScriptBuilder().AddOp(OP_1).AddData(q).Script()
	assert.Nil(t, err)

	// create a first random funding transaction to a pubkey and send to TaprootAddr
	txHash, err := chainhash.NewHashFromStr("aff48a9b83dc525d330ded64e1b6a9e127c99339f7246e2c89e06cd83493af9b") // this is a random hash
	assert.Nil(t, err)
	// create tx
	tx_1 := wire.NewMsgTx(2)
	tx_1.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  *txHash,
			Index: uint32(0),
		},
	})

	txOut := &wire.TxOut{
		Value: 1000000000, PkScript: p2taprootScript,
	}
	tx_1.AddTxOut(txOut)

	sig, err := txscript.SignatureScript(tx_1, 0, []byte{}, txscript.SigHashDefault, keypair.priv, true)
	assert.Nil(t, err)
	tx_1.TxIn[0].SignatureScript = sig

	// add the transaction to the blockchain
	blockUtxos := blockchain.NewUtxoViewpoint()
	blockUtxos.AddTxOut(btcutil.NewTx(tx_1), 0, 0)

	// create a second transaction to spend the first transaction
	tx_2 := wire.NewMsgTx(2)
	tx_2.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  tx_1.TxHash(),
			Index: uint32(0),
		},
	})

	txOut_2 := &wire.TxOut{
		Value: 1000000000, PkScript: nil, // this is a random pkscript
	}
	tx_2.AddTxOut(txOut_2)

	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		tx_1.TxOut[0].PkScript,
		tx_1.TxOut[0].Value,
	)

	sigHashes := txscript.NewTxSigHashes(tx_2, inputFetcher)

	signature, err := txscript.RawTxInTaprootSignature(tx_2, sigHashes, 0, 1000000000, p2taprootScript, rootcommitment[:], txscript.SigHashAll, keypair.priv)
	assert.Nil(t, err)

	tx_2.TxIn[0].Witness = wire.TxWitness{signature}

	sigCache := txscript.NewSigCache(5)
	hashCache := txscript.NewHashCache(5)

	err = blockchain.ValidateTransactionScripts(
		btcutil.NewTx(tx_2), blockUtxos, txscript.StandardVerifyFlags, sigCache, hashCache,
	)
	assert.Nil(s.t, err)
}

func TestTaprootUsingScriptSpendingPath(t *testing.T) {
	s := TestSuite{}
	s.setupStaticSimNetSuite(t)

	_, internalKeypair := s.newKeyPair("")
	_, keypair := s.newKeyPair("")

	builder := txscript.NewScriptBuilder()
	builder.AddData(schnorr.SerializePubKey(keypair.pub))
	//
	builder.AddOp(txscript.OP_CHECKSIG)

	p2pkScript, err := builder.Script()
	assert.Nil(t, err)

	tapleaf := txscript.NewBaseTapLeaf(p2pkScript)
	taptree := txscript.AssembleTaprootScriptTree(tapleaf)
	controlblock := taptree.LeafMerkleProofs[0].ToControlBlock(internalKeypair.pub)
	ctrBlockBytes, err := controlblock.ToBytes()
	assert.Nil(t, err)

	rootCommitment := taptree.RootNode.TapHash()

	taprootOutputKey := txscript.ComputeTaprootOutputKey(internalKeypair.pub, rootCommitment[:])
	assert.NotNil(t, taprootOutputKey)

	taprootAddr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(taprootOutputKey), s.btcdChainConfig)
	assert.Nil(t, err)
	assert.NotNil(t, taprootAddr)

	p2taprootScript, err := txscript.PayToAddrScript(taprootAddr)
	assert.Nil(t, err)

	// create a first random funding transaction to a pubkey and send to TaprootAddr
	tx_1 := createTxSendToTaprootAddress(t, p2taprootScript, internalKeypair.priv)

	// add the transaction to the blockchain
	blockUtxos := blockchain.NewUtxoViewpoint()
	blockUtxos.AddTxOut(btcutil.NewTx(tx_1), 0, 0)

	// create a second transaction to spend the first transaction
	tx_2 := wire.NewMsgTx(2)
	tx_2.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  tx_1.TxHash(),
			Index: uint32(0),
		},
	})

	txOut_2 := &wire.TxOut{
		Value: 1000000000, PkScript: nil, // this is a random pkscript
	}

	tx_2.AddTxOut(txOut_2)

	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		tx_1.TxOut[0].PkScript,
		tx_1.TxOut[0].Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx_2, inputFetcher)
	tapscriptSigHash, err := txscript.CalcTapscriptSignaturehash(sigHashes, txscript.SigHashDefault, tx_2, 0, inputFetcher, tapleaf)
	assert.Nil(t, err)
	assert.NotNil(t, tapscriptSigHash)

	sig, err := schnorr.Sign(keypair.priv, tapscriptSigHash[:])
	assert.Nil(t, err)

	oke := sig.Verify(tapscriptSigHash[:], keypair.pub)
	assert.True(t, oke)

	tx_2.TxIn[0].Witness = wire.TxWitness{sig.Serialize(), tapleaf.Script, ctrBlockBytes}

	sigCache := txscript.NewSigCache(5)
	hashCache := txscript.NewHashCache(5)

	err = blockchain.ValidateTransactionScripts(
		btcutil.NewTx(tx_2), blockUtxos, txscript.StandardVerifyFlags, sigCache, hashCache,
	)
	assert.Nil(s.t, err)
}

func TestTaprootWithMultiSignature(t *testing.T) {
	s := TestSuite{}
	s.setupStaticSimNetSuite(t)

	_, internalKeypair := s.newKeyPair("")
	_, keypair1 := s.newKeyPair("")
	_, keypair2 := s.newKeyPair("")

	aggrPub, _, _, err := musig2.AggregateKeys([]*secp256k1.PublicKey{keypair1.pub, keypair2.pub}, false)
	assert.Nil(t, err)

	builder := txscript.NewScriptBuilder()
	builder.AddData(schnorr.SerializePubKey(aggrPub.FinalKey))
	//
	builder.AddOp(txscript.OP_CHECKSIG)

	p2pkScript, err := builder.Script()
	assert.Nil(t, err)

	tapleaf := txscript.NewBaseTapLeaf(p2pkScript)
	taptree := txscript.AssembleTaprootScriptTree(tapleaf)
	controlblock := taptree.LeafMerkleProofs[0].ToControlBlock(internalKeypair.pub)
	ctrBlockBytes, err := controlblock.ToBytes()
	assert.Nil(t, err)

	rootCommitment := taptree.RootNode.TapHash()

	taprootOutputKey := txscript.ComputeTaprootOutputKey(internalKeypair.pub, rootCommitment[:])
	assert.NotNil(t, taprootOutputKey)

	taprootAddr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(taprootOutputKey), s.btcdChainConfig)
	assert.Nil(t, err)
	assert.NotNil(t, taprootAddr)

	p2taprootScript, err := txscript.PayToAddrScript(taprootAddr)
	assert.Nil(t, err)

	// create a first random funding transaction to a pubkey and send to TaprootAddr
	tx_1 := createTxSendToTaprootAddress(t, p2taprootScript, internalKeypair.priv)

	// add the transaction to the blockchain
	blockUtxos := blockchain.NewUtxoViewpoint()
	blockUtxos.AddTxOut(btcutil.NewTx(tx_1), 0, 0)

	// create a second transaction to spend the first transaction
	tx_2 := wire.NewMsgTx(2)
	tx_2.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  tx_1.TxHash(),
			Index: uint32(0),
		},
	})

	txOut_2 := &wire.TxOut{
		Value: 1000000000, PkScript: nil, // this is a random pkscript
	}

	tx_2.AddTxOut(txOut_2)

	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		tx_1.TxOut[0].PkScript,
		tx_1.TxOut[0].Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx_2, inputFetcher)
	tapscriptSigHash, err := txscript.CalcTapscriptSignaturehash(sigHashes, txscript.SigHashDefault, tx_2, 0, inputFetcher, tapleaf)
	assert.Nil(t, err)
	assert.NotNil(t, tapscriptSigHash)

	// Generate a nonce
	nonce1, err := musig2.GenNonces(musig2.WithPublicKey(keypair1.pub))
	assert.Nil(t, err)

	nonce2, err := musig2.GenNonces(musig2.WithPublicKey(keypair2.pub))
	assert.Nil(t, err)

	// aggregate the nonce
	aggrNonce, err := musig2.AggregateNonces([][66]byte{nonce1.PubNonce, nonce2.PubNonce})
	assert.Nil(t, err)

	sig1, err := musig2.Sign(nonce1.SecNonce, keypair1.priv, aggrNonce, []*secp256k1.PublicKey{keypair1.pub, keypair2.pub}, [32]byte(tapscriptSigHash))
	assert.Nil(t, err)

	sig2, err := musig2.Sign(nonce2.SecNonce, keypair2.priv, aggrNonce, []*secp256k1.PublicKey{keypair1.pub, keypair2.pub}, [32]byte(tapscriptSigHash))
	assert.Nil(t, err)

	sig := musig2.CombineSigs(sig1.R, []*musig2.PartialSignature{sig1, sig2})
	ok := sig.Verify(tapscriptSigHash, aggrPub.FinalKey)
	assert.True(t, ok)

	tx_2.TxIn[0].Witness = wire.TxWitness{sig.Serialize(), tapleaf.Script, ctrBlockBytes}

	sigCache := txscript.NewSigCache(5)
	hashCache := txscript.NewHashCache(5)

	err = blockchain.ValidateTransactionScripts(
		btcutil.NewTx(tx_2), blockUtxos, txscript.StandardVerifyFlags, sigCache, hashCache,
	)
	assert.Nil(s.t, err)
}

func TestOPCHECKSIGADD(t *testing.T) {
	s := TestSuite{}
	s.setupStaticSimNetSuite(t)

	_, internalKeypair := s.newKeyPair("")
	_, keypair1 := s.newKeyPair("")
	_, keypair2 := s.newKeyPair("")
	_, keypair3 := s.newKeyPair("")

	builder := txscript.NewScriptBuilder()

	builder.AddData(schnorr.SerializePubKey(keypair1.pub))
	builder.AddOp(txscript.OP_CHECKSIG)
	builder.AddData(schnorr.SerializePubKey(keypair2.pub))
	builder.AddOp(txscript.OP_CHECKSIGADD)
	builder.AddData(schnorr.SerializePubKey(keypair3.pub))
	builder.AddOp(txscript.OP_CHECKSIGADD)
	builder.AddOp(txscript.OP_2)
	builder.AddOp(txscript.OP_EQUAL)

	p2pkScript, err := builder.Script()
	assert.Nil(t, err)

	tapleaf := txscript.NewBaseTapLeaf(p2pkScript)
	taptree := txscript.AssembleTaprootScriptTree(tapleaf)
	controlblock := taptree.LeafMerkleProofs[0].ToControlBlock(internalKeypair.pub)
	ctrBlockBytes, err := controlblock.ToBytes()
	assert.Nil(t, err)

	rootCommitment := taptree.RootNode.TapHash()

	taprootOutputKey := txscript.ComputeTaprootOutputKey(internalKeypair.pub, rootCommitment[:])
	assert.NotNil(t, taprootOutputKey)

	taprootAddr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(taprootOutputKey), s.btcdChainConfig)
	assert.Nil(t, err)
	assert.NotNil(t, taprootAddr)

	p2taprootScript, err := txscript.PayToAddrScript(taprootAddr)
	assert.Nil(t, err)

	// create a first random funding transaction to a pubkey and send to TaprootAddr
	tx_1 := createTxSendToTaprootAddress(t, p2taprootScript, internalKeypair.priv)

	// add the transaction to the blockchain
	blockUtxos := blockchain.NewUtxoViewpoint()
	blockUtxos.AddTxOut(btcutil.NewTx(tx_1), 0, 0)

	// create a second transaction to spend the first transaction
	tx_2 := wire.NewMsgTx(2)
	tx_2.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  tx_1.TxHash(),
			Index: uint32(0),
		},
	})

	txOut_2 := &wire.TxOut{
		Value: 1000000000, PkScript: nil, // this is a random pkscript
	}

	tx_2.AddTxOut(txOut_2)

	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		tx_1.TxOut[0].PkScript,
		tx_1.TxOut[0].Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx_2, inputFetcher)
	tapscriptSigHash, err := txscript.CalcTapscriptSignaturehash(sigHashes, txscript.SigHashDefault, tx_2, 0, inputFetcher, tapleaf)
	assert.Nil(t, err)
	assert.NotNil(t, tapscriptSigHash)

	sig_1, err := txscript.RawTxInTapscriptSignature(tx_2, sigHashes, 0, 1000000000, p2pkScript, tapleaf, txscript.SigHashDefault, keypair1.priv)
	assert.Nil(t, err)

	sig_2, err := []byte{}, nil
	assert.Nil(t, err)

	sig_3, err := txscript.RawTxInTapscriptSignature(tx_2, sigHashes, 0, 1000000000, p2pkScript, tapleaf, txscript.SigHashDefault, keypair3.priv)
	assert.Nil(t, err)

	tx_2.TxIn[0].Witness = wire.TxWitness{sig_3, sig_2, sig_1, tapleaf.Script, ctrBlockBytes}

	sigCache := txscript.NewSigCache(5)
	hashCache := txscript.NewHashCache(5)

	err = blockchain.ValidateTransactionScripts(
		btcutil.NewTx(tx_2), blockUtxos, txscript.StandardVerifyFlags, sigCache, hashCache,
	)
	assert.Nil(s.t, err)
}

func createTxSendToTaprootAddress(t *testing.T, p2taprootScript []byte, privkey *btcec.PrivateKey) *wire.MsgTx {
	// create a first random funding transaction to a pubkey and send to TaprootAddr
	txHash, err := chainhash.NewHashFromStr("aff48a9b83dc525d330ded64e1b6a9e127c99339f7246e2c89e06cd83493af9b") // this is a random hash
	assert.Nil(t, err)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  *txHash,
			Index: uint32(0),
		},
	})

	txOut := &wire.TxOut{
		Value: 1000000000, PkScript: p2taprootScript,
	}

	tx.AddTxOut(txOut)

	sig, err := txscript.SignatureScript(tx, 0, []byte{}, txscript.SigHashDefault, privkey, true)
	assert.Nil(t, err)
	tx.TxIn[0].SignatureScript = sig

	return tx
}
