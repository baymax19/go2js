package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/gopherjs/gopherjs/js"
	"github.com/tendermint/tendermint/crypto"
	cryptoAmino "github.com/tendermint/tendermint/crypto/encoding/amino"
	"github.com/tendermint/tendermint/libs/bech32"
)

type AccAddress []byte

type MsgSend struct {
	Inputs  []Input  `json:"inputs"`
	Outputs []Output `json:"outputs"`
}
type Input struct {
	Address AccAddress `json:"address"`
	Coins   Coins      `json:"coins"`
}

type Output struct {
	Address AccAddress `json:"address"`
	Coins   Coins      `json:"coins"`
}

type Coins []Coin

type Coin struct {
	Denom  string `json:"denom"`
	Amount Int    `json:"amount"`
}

type Int struct {
	i *big.Int
}

func NewInt64Coin(denom string, amount int64) Coin {
	return NewCoin(denom, NewInt(amount))
}

func NewCoin(denom string, amount Int) Coin {
	if amount.LT(ZeroInt()) {
		panic(fmt.Sprintf("negative coin amount: %v\n", amount))
	}

	return Coin{
		Denom:  denom,
		Amount: amount,
	}
}

func NewInt(n int64) Int {
	return Int{big.NewInt(n)}
}

func (i Int) LT(i2 Int) bool {
	return lt(i.i, i2.i)
}

func lt(i *big.Int, i2 *big.Int) bool { return i.Cmp(i2) == -1 }

func ZeroInt() Int { return Int{big.NewInt(0)} }

func CreateMsg(from []byte, to []byte, coins Coins) Msg {
	input := NewInput(from, coins)
	output := NewOutput(to, coins)
	msg := NewMsgSend([]Input{input}, []Output{output})
	return msg
}

type Msg interface {
	Route() string
	Type() string
	ValidateBasic() error
	GetSignBytes() []byte
	GetSigners() []AccAddress
}

const MsgRoute = "bank"

func (msg MsgSend) Route() string { return MsgRoute }
func (msg MsgSend) Type() string  { return "send" }

// Implements Msg.
func (msg MsgSend) ValidateBasic() error {
	return nil
}

var msgCdc = codec.New()

// Return bytes to sign for Input
func (in Input) GetSignBytes() []byte {
	bin, err := msgCdc.MarshalJSON(in)
	if err != nil {
		panic(err)
	}
	return bin
}

// ValidateBasic - validate transaction input
func (in Input) ValidateBasic() error {
	return nil
}

// Implements Msg.
func (msg MsgSend) GetSignBytes() []byte {
	var inputs, outputs []json.RawMessage
	for _, input := range msg.Inputs {
		inputs = append(inputs, input.GetSignBytes())
	}
	for _, output := range msg.Outputs {
		outputs = append(outputs, output.GetSignBytes())
	}
	b, err := msgCdc.MarshalJSON(struct {
		Inputs  []json.RawMessage `json:"inputs"`
		Outputs []json.RawMessage `json:"outputs"`
	}{
		Inputs:  inputs,
		Outputs: outputs,
	})
	if err != nil {
		panic(err)
	}
	return b
}

// Implements Msg.
func (msg MsgSend) GetSigners() []AccAddress {
	addrs := make([]AccAddress, len(msg.Inputs))
	for i, in := range msg.Inputs {
		addrs[i] = in.Address
	}
	return addrs
}

func (out Output) GetSignBytes() []byte {
	bin, err := msgCdc.MarshalJSON(out)
	if err != nil {
		panic(err)
	}
	return bin
}

// ValidateBasic - validate transaction output
func (out Output) ValidateBasic() error {

	return nil
}
func NewInput(addr AccAddress, coins Coins) Input {
	input := Input{
		Address: addr,
		Coins:   coins,
	}
	return input
}
func NewOutput(addr AccAddress, coins Coins) Output {
	output := Output{
		Address: addr,
		Coins:   coins,
	}
	return output
}

func NewMsgSend(in []Input, out []Output) MsgSend {
	return MsgSend{Inputs: in, Outputs: out}
}

type StdTx struct {
	Msgs       []Msg          `json:"msg"`
	Fee        StdFee         `json:"fee"`
	Signatures []StdSignature `json:"signatures"`
	Memo       string         `json:"memo"`
}

// which must be above some miminum to be accepted into the mempool.
type StdFee struct {
	Amount Coins  `json:"amount"`
	Gas    uint64 `json:"gas"`
}

type StdSignature struct {
	crypto.PubKey `json:"pub_key"` // optional
	Signature     []byte           `json:"signature"`
}

func NewStdTx(msgs []Msg, fee StdFee, sigs []StdSignature, memo string) StdTx {
	return StdTx{
		Msgs:       msgs,
		Fee:        fee,
		Signatures: sigs,
		Memo:       memo,
	}
}

type Msgs []Msg

func (tx StdTx) GetMsgs() []Msg { return tx.Msgs }

func (tx StdTx) GetSigners() []AccAddress {
	seen := map[string]bool{}
	var signers []AccAddress
	for _, msg := range tx.GetMsgs() {
		for _, addr := range msg.GetSigners() {
			if !seen[addr.String()] {
				signers = append(signers, addr)
				seen[addr.String()] = true
			}
		}
	}
	return signers
}

func (tx StdTx) GetSignatures() []StdSignature { return tx.Signatures }

// String implements the Stringer interface.
func (aa AccAddress) String() string {
	bech32Addr, err := bech32.ConvertAndEncode("cosmos", aa.Bytes())
	if err != nil {
		panic(err)
	}

	return bech32Addr
}

// Bytes returns the raw address bytes.
func (aa AccAddress) Bytes() []byte {
	return aa
}

func main() {
	js.Module.Get("exports").Set("buildAndSignAndBroadcast", buildAndSignAndBroadcast)
	//buildAndSign("from", "to", "100coins", "priv")
	//fmt.Println(res,err)
}

func buildAndSignAndBroadcast(from, to, coins, priv string) {

	_, fromAdd, err := bech32.DecodeAndConvert(from)

	if err != nil {
		panic(err)
	}

	_, toAdd, err := bech32.DecodeAndConvert(to)

	if err != nil {
		panic(err)
	}

	coinsVal := Coins{NewInt64Coin("STAKE", 1)}

	msg := CreateMsg(fromAdd, toAdd, coinsVal)

	privKeyBytes, err := hex.DecodeString(priv)
	if err != nil {
		panic(err)
	}

	privKey, err := cryptoAmino.PrivKeyFromBytes(privKeyBytes)
	if err != nil {
		panic(err)
	}

	msgBytes := msg.GetSignBytes()
	signBytes, _ := privKey.Sign(msgBytes)

	msgs := []Msg{msg}

	coinsFee := Coins{NewInt64Coin("SENT", 1)}
	fee := StdFee{
		Amount: coinsFee,
		Gas:    uint64(21000),
	}
	stdTx := NewStdTx(msgs, fee, nil, "")
	sign := StdSignature{
		PubKey:    privKey.PubKey(),
		Signature: signBytes,
	}
	signs := stdTx.GetSignatures()
	signs = append(signs, sign)
	stdTx.Signatures = signs
	fmt.Println("sign bytes", stdTx)

	cdc := *codec.New()
	bytess := cdc.MustMarshalBinaryLengthPrefixed(stdTx)

	cdc.RegisterConcrete(StdTx{}, "StdTx", nil)
	cdc.RegisterConcrete(MsgSend{}, "SendMsg", nil)
	cdc.RegisterConcrete(Input{}, "Input", nil)
	cdc.RegisterConcrete(Output{}, "OutPut", nil)
	cdc.RegisterConcrete(Coin{}, "coin", nil)
	cdc.RegisterConcrete(StdFee{}, "Fee", nil)
	cdc.RegisterConcrete(StdSignature{}, "stdSign", nil)
	cdc.RegisterInterface((*Msg)(nil), nil)

	//bytess, err := json.Marshal(stdTx)
	//if err != nil {
	//	panic(err)
	//}

	// fmt.Println("marshal bytes", hex.EncodeToString(bytess))
	fmt.Println(base64.StdEncoding.EncodeToString(bytess))

	//body := struct {
	//	Method  string   `json:"method"`
	//	JSONRPC string   `json:"jsonrpc"`
	//	Params  []string `json:"params"`
	//	ID      string   `json:"id"`
	//}{
	//	Method:  "broadcast_tx_sync",
	//	JSONRPC: "2.0",
	//	Params:  []string{"c2Fp"},
	//	ID:      "dontcare",
	//}
	//reqBody := new(bytes.Buffer)
	//_ = json.NewEncoder(reqBody).Encode(body)
	//fmt.Println(reqBody)
	//
	//res, err := http.Post(url, "application/json; charset=utf-8", reqBody)
	//fmt.Println(res, err)
	//resBytes, _ := ioutil.ReadAll(res.Body)
	//fmt.Println(resBytes)

}
