package main

import (
	"encoding/hex"
	"strings"

	"github.com/cosmos/cosmos-sdk/crypto/keys/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mintkey"
	bip39 "github.com/cosmos/go-bip39"
	"github.com/gopherjs/gopherjs/js"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/secp256k1"
	"github.com/tendermint/tendermint/libs/bech32"
)

const (
	// used for deriving seed from mnemonic
	defaultBIP39Passphrase = ""

	// bits of entropy to draw when creating a mnemonic
	defaultEntropySize = 256
)

type AccAddress []byte

type Info interface {
	GetType() string
	GetName() string
	GetPubKey() crypto.PubKey
	GetAddress() AccAddress
}
type AccountInfo struct {
	*js.Object
	Name    string `js:"name"`
	PubKey  string `js:"pubkey"`
	Address string `js:"address"`
	PrivKey string `js:"priv_key"`
}

type localInfo struct {
	Name         string        `json:"name"`
	PubKey       crypto.PubKey `json:"pubkey"`
	PrivKeyArmor string        `json:"privkey.armor"`
}

func newLocalInfo(name string, pub crypto.PubKey, privArmor string) Info {
	return &localInfo{
		Name:         name,
		PubKey:       pub,
		PrivKeyArmor: privArmor,
	}

}
func (i localInfo) GetName() string {
	return i.Name
}

func (i localInfo) GetType() string {
	return "local"
}

func (i localInfo) GetPubKey() crypto.PubKey {
	return i.PubKey
}

func (i localInfo) GetAddress() AccAddress {
	return i.PubKey.Address().Bytes()
}

func main() {
	js.Module.Get("exports").Set("createkey", createkey)
}

func createkey(name, password string) *js.Object {

	//entropy, err := bip39.NewEntropy(defaultEntropySize)
	//if err != nil {
	//	return ""
	//}
	//mnemonic, err := bip39.NewMnemonic(entropy)
	//if err != nil {
	//	return ""
	//}
	//
	//seed := bip39.NewSeed(mnemonic, defaultBIP39Passphrase)

	mnemonic := "horror guess faint sense sorry cloth medal autumn rocket census unfold bright loan swear agent tray city away hurt chunk hybrid race cash nice"
	seed := bip39.NewSeed(mnemonic, "")

	masterPriv, ch := hd.ComputeMastersFromSeed(seed)

	deriverdPriv, err := hd.DerivePrivateKeyForPath(masterPriv, ch, hd.FullFundraiserPath)
	if err != nil {
		panic(err)
	}

	privateKey := secp256k1.PrivKeySecp256k1(deriverdPriv)
	pubKey := secp256k1.PrivKeySecp256k1(deriverdPriv).PubKey()

	privKeyArmor := mintkey.EncryptArmorPrivKey(secp256k1.PrivKeySecp256k1(deriverdPriv), password)
	info := newLocalInfo(name, pubKey, privKeyArmor)

	//encode pubKey to bech32
	pubkeyCosmos, err := bech32.ConvertAndEncode("cosmospub", pubKey.Bytes())
	if err != nil {
		panic(err)
	}

	//encode accAddress to bech32
	addressCosmos, err := bech32.ConvertAndEncode("cosmos", info.GetPubKey().Address().Bytes())
	if err != nil {
		panic(err)
	}

	data := &AccountInfo{Object: js.Global.Get("Object").New()}
	data.Address = addressCosmos
	data.PubKey = pubkeyCosmos
	data.Name = name
	data.PrivKey = strings.ToUpper(hex.EncodeToString(privateKey.Bytes()))

	return data.Object
}
