package main

//import (
//	"encoding/json"
//	"fmt"
//	"github.com/cosmos/cosmos-sdk/client"
//	ckeys "github.com/cosmos/cosmos-sdk/client/keys"
//     "github.com/cosmos/cosmos-sdk/crypto/keys")
//
//func createKey(name , password string) error{
//	var kb keys.Keybase
//
//	kb,err:=ckeys.GetKeyBase()
//	if err!=nil{
//		panic(err)
//	}
//
//	seed := getSeed(keys.Secp256k1)
//
//	info, err := kb.CreateKey(name, seed, password)
//
//	output,err := ckeys.Bech32KeyOutput(info)
//	if err!=nil{
//		panic(err)
//	}
//
//	bz, err := json.Marshal(output)
//	if err!=nil{
//		panic(err)
//	}
//
//	fmt.Println(string(bz))
//	return nil
//
//
//}
//func main(){
//	createKey("rgukt123","sai")
//}
//func getSeed(algo keys.SigningAlgo) string {
//	kb := client.MockKeyBase()
//	pass := "throwing-this-key-away"
//	name := "inmemorykey"
//	_, seed, _ := kb.CreateMnemonic(name, keys.English, pass, algo)
//	return seed
//}