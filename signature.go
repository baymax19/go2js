package main

import (
	"encoding/hex"
	"github.com/gopherjs/gopherjs/js"
	"github.com/tendermint/tendermint/crypto/encoding/amino"
)

type SignatureInfo struct {
	*js.Object
	PrivKey string `js:"priv_key"`
	Message string `js:"message"`
}

func main() {
	js.Module.Get("exports").Set("sign", sign)
}

func sign(object *js.Object) string {

	signObj := &SignatureInfo{Object: object}

	privKeyBytes, err := hex.DecodeString(signObj.PrivKey)
	if err != nil {
		panic(err)
	}

	privKey, err := cryptoAmino.PrivKeyFromBytes(privKeyBytes)
	if err != nil {
		panic(err)
	}


	signBytes, err := privKey.Sign([]byte(signObj.Message))
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(signBytes)
}
