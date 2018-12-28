package main

//import (
//	"fmt"
//	keys2 "github.com/cosmos/cosmos-sdk/client/keys"
//	"github.com/cosmos/cosmos-sdk/crypto/keys"
//	"github.com/cosmos/go-bip39"
//	"math/big"
//)
//var (
//	Last11BitsMask          = big.NewInt(2047)
//	RightShift11BitsDivider = big.NewInt(2048)
//	BigOne                  = big.NewInt(1)
//	BigTwo                  = big.NewInt(2)
//)
//
//var ReverseWordMap map[string]int = map[string]int{}
//
//func main() {
//	var kb keys.Keybase
//
//	kb, err := keys2.GetKeyBase()
//	if err != nil {
//		panic(err)
//	}
//	fmt.Println(kb)
//
//	mnemonic := "wagon play rule enough thank segment student vault soda afraid connect senior prefer raise luxury pull fury point sausage time deliver buddy onion empower"
//	//password := "rgukt123"
//
//	//seed, err := bip39.NewSeedWithErrorChecking(mnemonic, password)
//	//if err!=nil{
//	//	panic(err)
//	//}
//
//
//	seed,err := MnemonicToByteArray(mnemonic)
//	if err!=nil{
//		panic(err)
//	}
//
//	seed = bip39.NewSeed(mnemonic,"")
//	fmt.Println(seed)
//}
