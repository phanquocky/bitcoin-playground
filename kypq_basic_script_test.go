package main

import (
	"crypto/sha256"
	"log"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/ecdsa"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
	"github.com/stretchr/testify/assert"
)

func sendToPubkeyScript(t *testing.T, pkscript []byte) *wire.MsgTx {
	// send to pubkey script
	tx := wire.NewMsgTx(2)
	txHash, err := chainhash.NewHashFromStr("aff48a9b83dc525d330ded64e1b6a9e127c99339f7246e2c89e06cd83493af9b")
	assert.Nil(t, err)

	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  *txHash,
			Index: 0,
		}})
	txOut := &wire.TxOut{
		Value: 2000000000, PkScript: pkscript,
	}
	tx.AddTxOut(txOut)

	return tx
}

func Test_P2PK(t *testing.T) {
	s := testhelper.TestSuite{}
	s.SetupStaticSimNetSuite(t, log.Default())
	_, keyPair := s.NewHDKeyPairFromSeed(ALICE_WALLET_SEED)

	// p2pkscript = <pubkey> OP_CHECKSIG
	p2pkscript, err := txscript.NewScriptBuilder().AddData(keyPair.Pub.SerializeCompressed()).AddOp(txscript.OP_CHECKSIG).Script()
	assert.Nil(t, err)

	tx := sendToPubkeyScript(t, p2pkscript)
	// add the transaction to the blockchain
	blockUtxos := blockchain.NewUtxoViewpoint()
	blockUtxos.AddTxOut(btcutil.NewTx(tx), 0, 0)

	// spend the transaction
	tx2 := wire.NewMsgTx(2)
	tx2.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  tx.TxHash(),
			Index: 0,
		}})
	tx2.AddTxOut(&wire.TxOut{
		Value: 1000000000, PkScript: keyPair.Pub.SerializeCompressed(),
	})

	// sign the transaction
	hash, err := txscript.CalcSignatureHash(p2pkscript, txscript.SigHashAll, tx2, 0)
	assert.Nil(t, err)

	signature := ecdsa.Sign(keyPair.GetTestPriv(), hash)

	sig := append(signature.Serialize(), byte(txscript.SigHashAll))

	//unlockscript = <sig>
	unlockscript, err := txscript.NewScriptBuilder().AddData(sig).Script()
	assert.Nil(t, err)

	tx2.TxIn[0].SignatureScript = unlockscript

	sigCache := txscript.NewSigCache(5)
	hashCache := txscript.NewHashCache(5)
	err = blockchain.ValidateTransactionScripts(
		btcutil.NewTx(tx2), blockUtxos, txscript.StandardVerifyFlags, sigCache, hashCache,
	)
	assert.Nil(s.T, err)
}

func Test_P2PKH(t *testing.T) {
	s := testhelper.TestSuite{}
	s.SetupStaticSimNetSuite(t, log.Default())
	_, keyPair := s.NewHDKeyPairFromSeed(ALICE_WALLET_SEED)

	// p2pkhscript = OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
	p2pkhscript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).AddData(btcutil.Hash160(keyPair.Pub.SerializeCompressed())).AddOp(txscript.OP_EQUALVERIFY).AddOp(txscript.OP_CHECKSIG).Script()
	assert.Nil(t, err)

	tx := sendToPubkeyScript(t, p2pkhscript)
	// add the transaction to the blockchain
	blockUtxos := blockchain.NewUtxoViewpoint()
	blockUtxos.AddTxOut(btcutil.NewTx(tx), 0, 0)

	// spend the transaction
	tx2 := wire.NewMsgTx(2)
	tx2.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  tx.TxHash(),
			Index: 0,
		}})
	tx2.AddTxOut(&wire.TxOut{
		Value: 1000000000, PkScript: keyPair.Pub.SerializeCompressed(),
	})

	// sign the transaction
	hash, err := txscript.CalcSignatureHash(p2pkhscript, txscript.SigHashAll, tx2, 0)
	assert.Nil(t, err)

	signature := ecdsa.Sign(keyPair.GetTestPriv(), hash)

	sig := append(signature.Serialize(), byte(txscript.SigHashAll))

	//unlockscript = <sig> <pubkey>
	unlockscript, err := txscript.NewScriptBuilder().AddData(sig).AddData(keyPair.Pub.SerializeCompressed()).Script()
	assert.Nil(t, err)

	tx2.TxIn[0].SignatureScript = unlockscript

	sigCache := txscript.NewSigCache(5)
	hashCache := txscript.NewHashCache(5)
	err = blockchain.ValidateTransactionScripts(
		btcutil.NewTx(tx2), blockUtxos, txscript.StandardVerifyFlags, sigCache, hashCache,
	)
	assert.Nil(s.T, err)
}

func Test_P2MS(t *testing.T) {
	s := testhelper.TestSuite{}
	s.SetupStaticSimNetSuite(t, log.Default())

	_, alicePair := s.NewHDKeyPairFromSeed(ALICE_WALLET_SEED)
	_, bobPair := s.NewHDKeyPairFromSeed(BOB_WALLET_SEED)
	_, oliviaPair := s.NewHDKeyPairFromSeed(OLIVIA_WALLET_SEED)

	// p2ms = OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_CHECKMULTISIG
	p2ms, err := txscript.NewScriptBuilder().AddOp(txscript.OP_2).AddData(alicePair.Pub.SerializeCompressed()).AddData(bobPair.Pub.SerializeCompressed()).AddData(oliviaPair.Pub.SerializeCompressed()).AddOp(txscript.OP_3).AddOp(txscript.OP_CHECKMULTISIG).Script()
	assert.Nil(t, err)

	tx := sendToPubkeyScript(t, p2ms)
	// add the transaction to the blockchain
	blockUtxos := blockchain.NewUtxoViewpoint()
	blockUtxos.AddTxOut(btcutil.NewTx(tx), 0, 0)

	// spend the transaction
	tx2 := wire.NewMsgTx(2)
	tx2.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  tx.TxHash(),
			Index: 0,
		}})
	tx2.AddTxOut(&wire.TxOut{
		Value: 1000000000, PkScript: alicePair.Pub.SerializeCompressed(),
	})

	// sign the transaction
	hash, err := txscript.CalcSignatureHash(p2ms, txscript.SigHashAll, tx2, 0)
	assert.Nil(t, err)

	aliceSignature := ecdsa.Sign(alicePair.GetTestPriv(), hash)
	bobSignature := ecdsa.Sign(bobPair.GetTestPriv(), hash)

	aliceSig := append(aliceSignature.Serialize(), byte(txscript.SigHashAll))
	bobSig := append(bobSignature.Serialize(), byte(txscript.SigHashAll))

	//unlockscript = 0 <alice_sig> <bob_sig>
	unlockscript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(aliceSig).AddData(bobSig).Script()
	assert.Nil(t, err)

	tx2.TxIn[0].SignatureScript = unlockscript

	sigCache := txscript.NewSigCache(5)
	hashCache := txscript.NewHashCache(5)
	err = blockchain.ValidateTransactionScripts(
		btcutil.NewTx(tx2), blockUtxos, txscript.StandardVerifyFlags, sigCache, hashCache,
	)
	assert.Nil(s.T, err)
}

func Test_P2SH(t *testing.T) {
	s := testhelper.TestSuite{}
	s.SetupStaticSimNetSuite(t, log.Default())

	_, alicePair := s.NewHDKeyPairFromSeed(ALICE_WALLET_SEED)
	_, bobPair := s.NewHDKeyPairFromSeed(BOB_WALLET_SEED)
	_, oliviaPair := s.NewHDKeyPairFromSeed(OLIVIA_WALLET_SEED)

	// p2ms = OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_CHECKMULTISIG
	p2ms, err := txscript.NewScriptBuilder().AddOp(txscript.OP_2).AddData(alicePair.Pub.SerializeCompressed()).AddData(bobPair.Pub.SerializeCompressed()).AddData(oliviaPair.Pub.SerializeCompressed()).AddOp(txscript.OP_3).AddOp(txscript.OP_CHECKMULTISIG).Script()
	assert.Nil(t, err)

	// p2sh = OP_HASH160 <hash160(script)> OP_EQUAL
	p2shscript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_HASH160).AddData(btcutil.Hash160(p2ms)).AddOp(txscript.OP_EQUAL).Script()
	assert.Nil(t, err)

	tx := sendToPubkeyScript(t, p2shscript)
	// add the transaction to the blockchain
	blockUtxos := blockchain.NewUtxoViewpoint()
	blockUtxos.AddTxOut(btcutil.NewTx(tx), 0, 0)

	// spend the transaction
	tx2 := wire.NewMsgTx(2)
	tx2.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  tx.TxHash(),
			Index: 0,
		}})
	tx2.AddTxOut(&wire.TxOut{
		Value: 1000000000, PkScript: alicePair.Pub.SerializeCompressed(),
	})

	// sign the transaction
	hash, err := txscript.CalcSignatureHash(p2ms, txscript.SigHashAll, tx2, 0)
	assert.Nil(t, err)

	aliceSignature := ecdsa.Sign(alicePair.GetTestPriv(), hash)
	bobSignature := ecdsa.Sign(bobPair.GetTestPriv(), hash)

	aliceSig := append(aliceSignature.Serialize(), byte(txscript.SigHashAll))
	bobSig := append(bobSignature.Serialize(), byte(txscript.SigHashAll))

	//unlockscript = 0 <alice_sig> <bob_sig> <p2ms>
	unlockscript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(aliceSig).AddData(bobSig).AddData(p2ms).Script()
	assert.Nil(t, err)

	tx2.TxIn[0].SignatureScript = unlockscript

	sigCache := txscript.NewSigCache(5)
	hashCache := txscript.NewHashCache(5)
	err = blockchain.ValidateTransactionScripts(
		btcutil.NewTx(tx2), blockUtxos, txscript.StandardVerifyFlags, sigCache, hashCache,
	)
	assert.Nil(s.T, err)
}

func Test_P2WPKH(t *testing.T) {
	s := testhelper.TestSuite{}
	s.SetupStaticSimNetSuite(t, log.Default())

	_, keyPair := s.NewHDKeyPairFromSeed(ALICE_WALLET_SEED)
	// p2wpkhscript = OP_0 <pubkeyhash>
	p2wpkhscript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(btcutil.Hash160(keyPair.Pub.SerializeCompressed())).Script()
	assert.Nil(t, err)

	tx := sendToPubkeyScript(t, p2wpkhscript)
	// add the transaction to the blockchain
	blockUtxos := blockchain.NewUtxoViewpoint()
	blockUtxos.AddTxOut(btcutil.NewTx(tx), 0, 400)

	// spend the transaction
	tx2 := wire.NewMsgTx(2)
	tx2.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  tx.TxHash(),
			Index: 0,
		}})
	tx2.AddTxOut(&wire.TxOut{
		Value: 1000000000, PkScript: keyPair.Pub.SerializeCompressed(),
	})

	// sign the transaction
	inputFetcher := txscript.NewCannedPrevOutputFetcher(tx.TxOut[0].PkScript, tx.TxOut[0].Value)
	sigHash := txscript.NewTxSigHashes(tx2, inputFetcher)
	witnessSigHash, err := txscript.CalcWitnessSigHash(tx.TxOut[0].PkScript, sigHash, txscript.SigHashAll, tx2, 0, tx.TxOut[0].Value)
	assert.Nil(t, err)

	signature := ecdsa.Sign(keyPair.GetTestPriv(), witnessSigHash)
	sig := append(signature.Serialize(), byte(txscript.SigHashAll))

	// witness = <sig> <pubkey>
	tx2.TxIn[0].Witness = wire.TxWitness{sig, keyPair.Pub.SerializeCompressed()}

	sigCache := txscript.NewSigCache(5)
	hashCache := txscript.NewHashCache(5)

	err = blockchain.ValidateTransactionScripts(
		btcutil.NewTx(tx2), blockUtxos, txscript.ScriptVerifyWitness|txscript.ScriptBip16, sigCache, hashCache,
	)
	assert.Nil(s.T, err)

}

func Test_P2WSH(t *testing.T) {
	s := testhelper.TestSuite{}
	s.SetupStaticSimNetSuite(t, log.Default())

	_, alicePair := s.NewHDKeyPairFromSeed(ALICE_WALLET_SEED)
	_, bobPair := s.NewHDKeyPairFromSeed(BOB_WALLET_SEED)
	_, oliviaPair := s.NewHDKeyPairFromSeed(OLIVIA_WALLET_SEED)

	// p2ms = OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_CHECKMULTISIG
	p2ms, err := txscript.NewScriptBuilder().AddOp(txscript.OP_2).AddData(alicePair.Pub.SerializeCompressed()).AddData(bobPair.Pub.SerializeCompressed()).AddData(oliviaPair.Pub.SerializeCompressed()).AddOp(txscript.OP_3).AddOp(txscript.OP_CHECKMULTISIG).Script()
	assert.Nil(t, err)

	// p2wsh = OP_0 <sha256(script)>
	hasher := sha256.New()
	hasher.Write(p2ms)
	p2wshscript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(hasher.Sum(nil)).Script()
	assert.Nil(t, err)

	tx := sendToPubkeyScript(t, p2wshscript)
	// add the transaction to the blockchain
	blockUtxos := blockchain.NewUtxoViewpoint()
	blockUtxos.AddTxOut(btcutil.NewTx(tx), 0, 0)

	// spend the transaction
	tx2 := wire.NewMsgTx(2)
	tx2.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  tx.TxHash(),
			Index: 0,
		}})
	tx2.AddTxOut(&wire.TxOut{
		Value: 1000000000, PkScript: alicePair.Pub.SerializeCompressed(),
	})

	// sign the transaction
	inputFetcher := txscript.NewCannedPrevOutputFetcher(tx.TxOut[0].PkScript, tx.TxOut[0].Value)
	sigHash := txscript.NewTxSigHashes(tx2, inputFetcher)
	witnessSigHash, err := txscript.CalcWitnessSigHash(p2ms, sigHash, txscript.SigHashAll, tx2, 0, tx.TxOut[0].Value)
	assert.Nil(t, err)

	bobSignature := ecdsa.Sign(bobPair.GetTestPriv(), witnessSigHash)
	bobSig := append(bobSignature.Serialize(), byte(txscript.SigHashAll))

	aliceSignature := ecdsa.Sign(alicePair.GetTestPriv(), witnessSigHash)
	aliceSig := append(aliceSignature.Serialize(), byte(txscript.SigHashAll))

	//witness = 0 <alice_sig> <bob_sig> <p2ms>
	tx2.TxIn[0].Witness = wire.TxWitness{[]byte{}, aliceSig, bobSig, p2ms}

	sigCache := txscript.NewSigCache(5)
	hashCache := txscript.NewHashCache(5)
	err = blockchain.ValidateTransactionScripts(
		btcutil.NewTx(tx2), blockUtxos, txscript.ScriptVerifyWitness|txscript.ScriptBip16, sigCache, hashCache,
	)
	assert.Nil(s.T, err)
}
