// btcwallet --simnet --create --btcdusername=admin --btcdpassword=admin123 --walletpass=admin
// btcd --simnet --txindex --rpcuser=admin --rpcpass=admin123

// btcctl --simnet --wallet --rpcuser=admin --rpcpass=admin123  getbalance
// btcctl --simnet --wallet --rpcuser=admin --rpcpass=admin123  getnewaddress  --> SaFDbvdtrBxNxeFndG1kBsnk7SChPEuaaD

// btcd --simnet --txindex --rpcuser=admin --rpcpass=admin123 --miningaddr=SaFDbvdtrBxNxeFndG1kBsnk7SChPEuaaD

// btcctl --simnet --wallet --rpcuser=admin --rpcpass=admin123 generate 100
// btcctl --simnet --wallet --rpcuser=admin --rpcpass=admin123 getbalance --> 50
package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func main() {
	// Only override the handlers for notifications you care about.
	// Also note most of the handlers will only be called if you register
	// for notifications.  See the documentation of the rpcclient
	// NotificationHandlers type for more details about each handler.
	ntfnHandlers := rpcclient.NotificationHandlers{
		OnAccountBalance: func(account string, balance btcutil.Amount, confirmed bool) {
			log.Printf("New balance for account %s: %v", account,
				balance)
		},
	}

	// Connect to local btcwallet RPC server using websockets.
	certHomeDir := btcutil.AppDataDir("btcwallet", false)
	certs, err := os.ReadFile(filepath.Join(certHomeDir, "rpc.cert"))
	if err != nil {
		log.Fatal(err)
	}
	connCfg := &rpcclient.ConnConfig{
		Host:         "localhost:18554",
		Endpoint:     "ws",
		User:         "admin",
		Pass:         "admin123",
		Certificates: certs,
	}
	client, err := rpcclient.New(connCfg, &ntfnHandlers)
	if err != nil {
		log.Fatal(err)
	}

	// Get the list of unspent transaction outputs (utxos) that the
	// connected wallet has at least one private key for.
	unspent, err := client.ListUnspent()
	if err != nil {
		log.Fatal(err)
	}

	//SaFDbvdtrBxNxeFndG1kBsnk7SChPEuaaD

	address, err := btcutil.DecodeAddress("SaFDbvdtrBxNxeFndG1kBsnk7SChPEuaaD", &chaincfg.SimNetParams)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("address: %v", address)

	pkscript, err := txscript.PayToAddrScript(address)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("pkscript: ", pkscript)

	// transfer this utxo to SaFDbvdtrBxNxeFndG1kBsnk7SChPEuaaD address
	tx := wire.NewMsgTx(2)

	amount := int64(100)
	Fee := int64(1000)
	inputAmount := int64(0)
	idx := 0
	for inputAmount < (amount + Fee) {
		inputAmount += int64(unspent[idx].Amount) * 1e8

		txhash, err := chainhash.NewHashFromStr(unspent[idx].TxID)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("txhash: %v", txhash)
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(txhash, unspent[idx].Vout), nil, nil))
		idx++
	}

	// tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(txhash, unspent[0].Vout), nil, nil))
	tx.AddTxOut(wire.NewTxOut(amount, pkscript))

	log.Println("tx: ", tx)

	err = client.WalletPassphrase("admin", 60)
	if err != nil {
		log.Fatal(err)
	}

	// Sign the single input with the single private key.
	tx, ok, err := client.SignRawTransaction(tx)
	if err != nil {
		fmt.Println("SignRawTransaction: ", err)
		log.Fatal(err)
	}
	if !ok {
		log.Fatal("Failed to sign transaction")
	}

	log.Println("tx: ", tx)
	var buffer bytes.Buffer
	err = tx.Serialize(&buffer)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("tx: %x", buffer.Bytes())

	_, err = client.SendRawTransaction(tx, true)
	if err != nil {
		log.Println("SendRawTransaction1: ", err)
		log.Fatal(err)
	}

	_, err = client.Generate(1)
	if err != nil {
		log.Println("Generate: ", err)
		log.Fatal(err)
	}

	_, err = client.SendRawTransaction(tx, true)
	if err != nil {
		log.Println("SendRawTransaction2: ", err)
		// log.Fatal(err)
	}

	// For this example gracefully shutdown the client after 10 seconds.
	// Ordinarily when to shutdown the client is highly application
	// specific.
	log.Println("Client shutdown in 10 seconds...")
	time.AfterFunc(time.Second*10, func() {
		log.Println("Client shutting down...")
		client.Shutdown()
		log.Println("Client shutdown complete.")
	})

	// Wait until the client either shuts down gracefully (or the user
	// terminates the process with Ctrl+C).
	client.WaitForShutdown()

}
