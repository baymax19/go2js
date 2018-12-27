package main

import (
	"fmt"

	ckeys "github.com/cosmos/cosmos-sdk/client/keys"
	"github.com/cosmos/cosmos-sdk/crypto/keys"

	"github.com/cosmos/cosmos-sdk/crypto/keys/hd"
	"github.com/cosmos/go-bip39"
	"os"
	//"github.com/gopherjs/gopherjs/js"
	//"syscall/js"
	"github.com/gopherjs/gopherwasm/js"
)

const mnemonicEntropySize = 256

func CreateKey(name, password string) error {
	var kb keys.Keybase

	kb, err := ckeys.GetKeyBaseWithWritePerm()
	if err != nil {
		return err
	}

	entropySeed, err := bip39.NewEntropy(mnemonicEntropySize)
	if err != nil {
		return err
	}

	mnemonic, err := bip39.NewMnemonic(entropySeed[:])
	if err != nil {
		return err
	}

	bip44Parms, err := hd.NewParamsFromPath("44'/118'/0'/0/0")
	if err != nil {
		return err
	}

	info, err := kb.Derive(name, mnemonic, "", password, *bip44Parms)
	if err != nil {
		return err
	}
	printCreate(info, mnemonic)
	return nil
}

func main() {
	js.Global.Get("export").Set("createKey", CreateKey)
}

func printCreate(info keys.Info, seed string) {
	out, err := ckeys.Bech32KeyOutput(info)
	if err != nil {
		panic(err)
	}
	var jsonString []byte

	jsonString, err = ckeys.MarshalJSON(out)
	if err != nil {
		panic(err) // really shouldn't happen...
	}
	fmt.Println(jsonString)
}
