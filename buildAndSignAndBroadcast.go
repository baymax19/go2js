package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/gopherjs/gopherjs/js"
	amino "github.com/tendermint/go-amino"
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

func NewStdFee(gas uint64, amount ...Coin) StdFee {
	return StdFee{
		Amount: amount,
		Gas:    gas,
	}
}

func newStdFee() StdFee {
	return NewStdFee(20000,
		NewInt64Coin("", 0),
	)
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

func CreateMsg(from AccAddress, to AccAddress, coins Coins) Msg {
	fmt.Println(from, to)
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

var msgCdc = amino.NewCodec()

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

func (fee StdFee) Bytes() []byte {
	// normalize. XXX
	// this is a sign of something ugly
	// (in the lcd_test, client side its null,
	// server side its [])
	if len(fee.Amount) == 0 {
		fee.Amount = Coins{}
	}
	bz, err := msgCdc.MarshalJSON(fee) // TODO
	if err != nil {
		panic(err)
	}
	return bz
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

// require access to any other information.
func (tx StdTx) ValidateBasic() error {

	return nil
}
func (tx StdTx) GetMemo() string { return tx.Memo }

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

//tx
type Tx []byte

type StdSignDoc struct {
	AccountNumber uint64            `json:"account_number"`
	ChainID       string            `json:"chain_id"`
	Fee           json.RawMessage   `json:"fee"`
	Memo          string            `json:"memo"`
	Msgs          []json.RawMessage `json:"msgs"`
	Sequence      uint64            `json:"sequence"`
}

func SortJSON(toSortJSON []byte) ([]byte, error) {
	var c interface{}
	err := json.Unmarshal(toSortJSON, &c)
	if err != nil {
		return nil, err
	}
	js, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return js, nil
}

// MustSortJSON is like SortJSON but panic if an error occurs, e.g., if
// the passed JSON isn't valid.
func MustSortJSON(toSortJSON []byte) []byte {
	js, err := SortJSON(toSortJSON)
	if err != nil {
		panic(err)
	}
	fmt.Println("types...utils..37 line", js)
	return js
}

func main() {
	js.Module.Get("exports").Set("buildAndSignAndBroadcast", buildAndSignAndBroadcast)
	//buildAndSign("from", "to", "100coins", "priv")
	//fmt.Println(res,err)
}

func buildAndSignAndBroadcast(from, to, coins, priv string) {

	msgCdc.RegisterInterface((*Msg)(nil), nil)
	msgCdc.RegisterConcrete(MsgSend{}, "cosmos-sdk/Send", nil)
	msgCdc.RegisterConcrete(StdTx{}, "auth/StdTx", nil)

	//	msgCdc.RegisterConcrete(Input{}, "Input", nil)
	//msgCdc.RegisterConcrete(Output{}, "OutPut", nil)
	msgCdc.RegisterConcrete(Coin{}, "coin", nil)
	// msgCdc.RegisterConcrete(StdFee{}, "Fee", nil)
	msgCdc.RegisterConcrete(StdSignature{}, "stdSign", nil)
	cryptoAmino.RegisterAmino(msgCdc)

	fromAdd, _ := AccAddressFromBech32(from)
	toAdd, _ := AccAddressFromBech32(to)

	// coi, _ := ParseCoin("1STAKE")
	coi := NewInt64Coin("STAKE", int64(1))
	coinsVal := Coins{coi}
	fmt.Println("bech32...decode.....", fromAdd, toAdd)
	fmt.Println("coinnnnnnnnnnnnnnnnn", coinsVal)
	msg := CreateMsg(fromAdd, toAdd, coinsVal)

	fmt.Println("the msg", msg)

	privKeyBytes, err := hex.DecodeString(priv)
	if err != nil {
		panic(err)
	}

	privKey, err := cryptoAmino.PrivKeyFromBytes(privKeyBytes)
	if err != nil {
		panic(err)
	}

	// msgBytes := msg.GetSignBytes()

	msgs := []Msg{msg}

	feeCoin := []Coin{NewCoin("", NewInt(0))}
	fee := NewStdFee(200000, feeCoin...)
	stdTx := NewStdTx(msgs, fee, nil, "")
	fmt.Println("111111111111111111")

	//fmt.Println("sign bytes", stdTx)

	// bytess := cdc.MustMarshalBinaryLengthPrefixed(stdTx)
	// fmt.Println(bytess)

	// broadcastPayload := struct {
	// 	Tx     StdTx  `json:"tx"`
	// 	Return string `json:"return"`
	// }{Tx: stdTx, Return: "block"}

	// json, err := msgCdc.MarshalJSON(broadcastPayload)
	// if err != nil {
	// 	panic(err)
	// }

	msgsss := stdTx.GetMsgs()
	var msgsBytes []json.RawMessage
	for _, msg := range msgsss {
		msgsBytes = append(msgsBytes, json.RawMessage(msg.GetSignBytes()))
	}
	var stdo StdSignDoc
	bz, err := msgCdc.MarshalJSON(StdSignDoc{
		AccountNumber: uint64(1),
		ChainID:       "sentinel-vpn",
		Fee:           json.RawMessage(fee.Bytes()),
		Memo:          "",
		Msgs:          msgsBytes,
		Sequence:      uint64(7),
	})
	if err != nil {
		panic(err)
	}
	_ = msgCdc.UnmarshalJSON(bz, &stdo)
	fmt.Println("doccccccccccccccccc", string(bz))
	fmt.Println("444444bzzzzzzzzzzzz", bz)

	js := MustSortJSON(bz)
	fmt.Println("jsssssssssssssssss", js)
	signBytes, _ := privKey.Sign(js)

	sign := StdSignature{
		PubKey:    privKey.PubKey(),
		Signature: signBytes,
	}

	signs := stdTx.GetSignatures()
	fmt.Println("6666666666666", signs)
	signs = append(signs, sign)
	stdTx.Signatures = signs

	data, err := msgCdc.MarshalJSON(stdTx)
	if err != nil {
		panic(err)
	}
	fmt.Println("std string", string(data))

	fmt.Println("sttttttttttd", stdTx)

	a, _ := msgCdc.MarshalBinaryLengthPrefixed(stdTx)
	fmt.Println(hex.EncodeToString(a))

	bs64 := base64.StdEncoding.EncodeToString(a)
	fmt.Println("cccccccccccccccc", bs64)

	// var res *http.Response

	// url := fmt.Sprintf("http://localhost:26657%v", "/broadcast_tx_commit?tx=")
	// //fmt.Printf("REQUEST %s %s\n", "GET", url)
	// val := bytes.NewBuffer(json)
	// req, err := http.NewRequest("GET", url, val)

	// res, err = http.DefaultClient.Do(req)
	// fmt.Println("111111111111111111")
	// output, err := ioutil.ReadAll(res.Body)
	// if err != nil {
	// 	panic(err)
	// }
	// res.Body.Close()

	// var resultTx ctypes.ResultBroadcastTxCommit
	// if err = cdc.UnmarshalJSON([]byte(string(output)), &resultTx); err != nil {
	// 	panic(err)
	// }
	//fmt.Println(string(output))

	//bytess, err := json.Marshal(stdTx)
	//if err != nil {
	//	panic(err)
	//}

	// fmt.Println("marshal bytes", hex.EncodeToString(bytess))
	// fmt.Println(base64.StdEncoding.EncodeToString(bytess))

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

func AccAddressFromHex(address string) (addr AccAddress, err error) {
	if len(address) == 0 {
		return addr, errors.New("decoding Bech32 address failed: must provide an address")
	}

	bz, err := hex.DecodeString(address)
	if err != nil {
		return nil, err
	}

	return AccAddress(bz), nil
}

// AccAddressFromBech32 creates an AccAddress from a Bech32 string.
func AccAddressFromBech32(address string) (addr AccAddress, err error) {
	bech32PrefixAccAddr := "cosmos"
	bz, err := GetFromBech32(address, bech32PrefixAccAddr)
	if err != nil {
		return nil, err
	}

	return AccAddress(bz), nil
}

// Returns boolean for whether two AccAddresses are Equal
func (aa AccAddress) Equals(aa2 AccAddress) bool {
	if aa.Empty() && aa2.Empty() {
		return true
	}

	return bytes.Compare(aa.Bytes(), aa2.Bytes()) == 0
}

// Returns boolean for whether an AccAddress is empty
func (aa AccAddress) Empty() bool {
	if aa == nil {
		return true
	}

	aa2 := AccAddress{}
	return bytes.Compare(aa.Bytes(), aa2.Bytes()) == 0
}

// Marshal returns the raw address bytes. It is needed for protobuf
// compatibility.
func (aa AccAddress) Marshal() ([]byte, error) {
	return aa, nil
}

// Unmarshal sets the address to the given data. It is needed for protobuf
// compatibility.
func (aa *AccAddress) Unmarshal(data []byte) error {
	*aa = data
	return nil
}

// MarshalJSON marshals to JSON using Bech32.
func (aa AccAddress) MarshalJSON() ([]byte, error) {
	return json.Marshal(aa.String())
}

// UnmarshalJSON unmarshals from JSON assuming Bech32 encoding.
func (aa *AccAddress) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}

	aa2, err := AccAddressFromBech32(s)
	if err != nil {
		return err
	}

	*aa = aa2
	return nil
}

// Bytes returns the raw address bytes.

// Format implements the fmt.Formatter interface.
// nolint: errcheck
func (aa AccAddress) Format(s fmt.State, verb rune) {
	switch verb {
	case 's':
		s.Write([]byte(fmt.Sprintf("%s", aa.String())))
	case 'p':
		s.Write([]byte(fmt.Sprintf("%p", aa)))
	default:
		s.Write([]byte(fmt.Sprintf("%X", []byte(aa))))
	}
}

func GetFromBech32(bech32str, prefix string) ([]byte, error) {
	if len(bech32str) == 0 {
		return nil, errors.New("decoding Bech32 address failed: must provide an address")
	}

	hrp, bz, err := bech32.DecodeAndConvert(bech32str)
	if err != nil {
		return nil, err
	}

	if hrp != prefix {
		return nil, fmt.Errorf("invalid Bech32 prefix; expected %s, got %s", prefix, hrp)
	}

	return bz, nil
}

// NewInt64Coin returns a new coin with a denomination and amount. It will panic
// if the amount is negative.

// String provides a human-readable representation of a coin
func (coin Coin) String() string {
	return fmt.Sprintf("%v%v", coin.Amount, coin.Denom)
}

// SameDenomAs returns true if the two coins are the same denom
func (coin Coin) SameDenomAs(other Coin) bool {
	return (coin.Denom == other.Denom)
}

// IsZero returns if this represents no money
func (coin Coin) IsZero() bool {
	return coin.Amount.IsZero()
}

// IsGTE returns true if they are the same type and the receiver is
// an equal or greater value
func (coin Coin) IsGTE(other Coin) bool {
	return coin.SameDenomAs(other) && (!coin.Amount.LT(other.Amount))
}

// IsLT returns true if they are the same type and the receiver is
// a smaller value
func (coin Coin) IsLT(other Coin) bool {
	return coin.SameDenomAs(other) && coin.Amount.LT(other.Amount)
}

// IsEqual returns true if the two sets of Coins have the same value
func (coin Coin) IsEqual(other Coin) bool {
	return coin.SameDenomAs(other) && (coin.Amount.Equal(other.Amount))
}

// Adds amounts of two coins with same denom. If the coins differ in denom then
// it panics.
func (coin Coin) Plus(coinB Coin) Coin {
	if !coin.SameDenomAs(coinB) {
		panic(fmt.Sprintf("invalid coin denominations; %s, %s", coin.Denom, coinB.Denom))
	}

	return Coin{coin.Denom, coin.Amount.Add(coinB.Amount)}
}

// Subtracts amounts of two coins with same denom. If the coins differ in denom
// then it panics.
func (coin Coin) Minus(coinB Coin) Coin {
	if !coin.SameDenomAs(coinB) {
		panic(fmt.Sprintf("invalid coin denominations; %s, %s", coin.Denom, coinB.Denom))
	}

	res := Coin{coin.Denom, coin.Amount.Sub(coinB.Amount)}
	if !res.IsNotNegative() {
		panic("negative count amount")
	}

	return res
}

// IsPositive returns true if coin amount is positive.
//
// TODO: Remove once unsigned integers are used.
func (coin Coin) IsPositive() bool {
	return (coin.Amount.Sign() == 1)
}

// IsNotNegative returns true if coin amount is not negative and false otherwise.
//
// TODO: Remove once unsigned integers are used.
func (coin Coin) IsNotNegative() bool {
	return (coin.Amount.Sign() != -1)
}

func (i Int) Sign() int {
	return i.i.Sign()
}

func (i Int) Sub(i2 Int) (res Int) {
	res = Int{sub(i.i, i2.i)}
	// Check overflow
	if res.i.BitLen() > 255 {
		panic("Int overflow")
	}
	return
}
func (i Int) Add(i2 Int) (res Int) {
	res = Int{add(i.i, i2.i)}
	// Check overflow
	if res.i.BitLen() > 255 {
		panic("Int overflow")
	}
	return
}
func (i Int) Equal(i2 Int) bool {
	return equal(i.i, i2.i)
}
func (i Int) IsZero() bool {
	return i.i.Sign() == 0
}
func sub(i *big.Int, i2 *big.Int) *big.Int { return new(big.Int).Sub(i, i2) }
func add(i *big.Int, i2 *big.Int) *big.Int { return new(big.Int).Add(i, i2) }
func equal(i *big.Int, i2 *big.Int) bool   { return i.Cmp(i2) == 0 }

func (coins Coins) String() string {
	if len(coins) == 0 {
		return ""
	}

	out := ""
	for _, coin := range coins {
		out += fmt.Sprintf("%v,", coin.String())
	}
	return out[:len(out)-1]
}

// IsValid asserts the Coins are sorted and have positive amounts.
func (coins Coins) IsValid() bool {
	switch len(coins) {
	case 0:
		return true
	case 1:
		return coins[0].IsPositive()
	default:
		lowDenom := coins[0].Denom

		for _, coin := range coins[1:] {
			if coin.Denom <= lowDenom {
				return false
			}
			if !coin.IsPositive() {
				return false
			}

			// we compare each coin against the last denom
			lowDenom = coin.Denom
		}

		return true
	}
}

// Plus adds two sets of coins.
//
// e.g.
// {2A} + {A, 2B} = {3A, 2B}
// {2A} + {0B} = {2A}
//
// NOTE: Plus operates under the invariant that coins are sorted by
// denominations.
//
// CONTRACT: Plus will never return Coins where one Coin has a non-positive
// amount. In otherwords, IsValid will always return true.
func (coins Coins) Plus(coinsB Coins) Coins {
	return coins.safePlus(coinsB)
}

// safePlus will perform addition of two coins sets. If both coin sets are
// empty, then an empty set is returned. If only a single set is empty, the
// other set is returned. Otherwise, the coins are compared in order of their
// denomination and addition only occurs when the denominations match, otherwise
// the coin is simply added to the sum assuming it's not zero.
func (coins Coins) safePlus(coinsB Coins) Coins {
	sum := ([]Coin)(nil)
	indexA, indexB := 0, 0
	lenA, lenB := len(coins), len(coinsB)

	for {
		if indexA == lenA {
			if indexB == lenB {
				// return nil coins if both sets are empty
				return sum
			}

			// return set B (excluding zero coins) if set A is empty
			return append(sum, removeZeroCoins(coinsB[indexB:])...)
		} else if indexB == lenB {
			// return set A (excluding zero coins) if set B is empty
			return append(sum, removeZeroCoins(coins[indexA:])...)
		}

		coinA, coinB := coins[indexA], coinsB[indexB]

		switch strings.Compare(coinA.Denom, coinB.Denom) {
		case -1: // coin A denom < coin B denom
			if !coinA.IsZero() {
				sum = append(sum, coinA)
			}

			indexA++

		case 0: // coin A denom == coin B denom
			res := coinA.Plus(coinB)
			if !res.IsZero() {
				sum = append(sum, res)
			}

			indexA++
			indexB++

		case 1: // coin A denom > coin B denom
			if !coinB.IsZero() {
				sum = append(sum, coinB)
			}

			indexB++
		}
	}
}

// Minus subtracts a set of coins from another.
//
// e.g.
// {2A, 3B} - {A} = {A, 3B}
// {2A} - {0B} = {2A}
// {A, B} - {A} = {B}
//
// CONTRACT: Minus will never return Coins where one Coin has a non-positive
// amount. In otherwords, IsValid will always return true.
func (coins Coins) Minus(coinsB Coins) Coins {
	diff, hasNeg := coins.SafeMinus(coinsB)
	if hasNeg {
		panic("negative coin amount")
	}

	return diff
}

// SafeMinus performs the same arithmetic as Minus but returns a boolean if any
// negative coin amount was returned.
func (coins Coins) SafeMinus(coinsB Coins) (Coins, bool) {
	diff := coins.safePlus(coinsB.negative())
	return diff, !diff.IsNotNegative()
}

// IsAllGT returns true iff for every denom in coins, the denom is present at a
// greater amount in coinsB.
func (coins Coins) IsAllGT(coinsB Coins) bool {
	diff, _ := coins.SafeMinus(coinsB)
	if len(diff) == 0 {
		return false
	}

	return diff.IsPositive()
}

// IsAllGTE returns true iff for every denom in coins, the denom is present at
// an equal or greater amount in coinsB.
func (coins Coins) IsAllGTE(coinsB Coins) bool {
	diff, _ := coins.SafeMinus(coinsB)
	if len(diff) == 0 {
		return true
	}

	return diff.IsNotNegative()
}

// IsAllLT returns True iff for every denom in coins, the denom is present at
// a smaller amount in coinsB.
func (coins Coins) IsAllLT(coinsB Coins) bool {
	return coinsB.IsAllGT(coins)
}

// IsAllLTE returns true iff for every denom in coins, the denom is present at
// a smaller or equal amount in coinsB.
func (coins Coins) IsAllLTE(coinsB Coins) bool {
	return coinsB.IsAllGTE(coins)
}

// IsZero returns true if there are no coins or all coins are zero.
func (coins Coins) IsZero() bool {
	for _, coin := range coins {
		if !coin.IsZero() {
			return false
		}
	}
	return true
}

// IsEqual returns true if the two sets of Coins have the same value
func (coins Coins) IsEqual(coinsB Coins) bool {
	if len(coins) != len(coinsB) {
		return false
	}

	coins = coins.Sort()
	coinsB = coinsB.Sort()

	for i := 0; i < len(coins); i++ {
		if coins[i].Denom != coinsB[i].Denom || !coins[i].Amount.Equal(coinsB[i].Amount) {
			return false
		}
	}

	return true
}

// Empty returns true if there are no coins and false otherwise.
func (coins Coins) Empty() bool {
	return len(coins) == 0
}

// Returns the amount of a denom from coins
func (coins Coins) AmountOf(denom string) Int {
	switch len(coins) {
	case 0:
		return ZeroInt()

	case 1:
		coin := coins[0]
		if coin.Denom == denom {
			return coin.Amount
		}
		return ZeroInt()

	default:
		midIdx := len(coins) / 2 // 2:1, 3:1, 4:2
		coin := coins[midIdx]

		if denom < coin.Denom {
			return coins[:midIdx].AmountOf(denom)
		} else if denom == coin.Denom {
			return coin.Amount
		} else {
			return coins[midIdx+1:].AmountOf(denom)
		}
	}
}

// IsPositive returns true if there is at least one coin and all currencies
// have a positive value.
//
// TODO: Remove once unsigned integers are used.
func (coins Coins) IsPositive() bool {
	if len(coins) == 0 {
		return false
	}

	for _, coin := range coins {
		if !coin.IsPositive() {
			return false
		}
	}

	return true
}

// IsNotNegative returns true if there is no coin amount with a negative value
// (even no coins is true here).
//
// TODO: Remove once unsigned integers are used.
func (coins Coins) IsNotNegative() bool {
	if len(coins) == 0 {
		return true
	}

	for _, coin := range coins {
		if !coin.IsNotNegative() {
			return false
		}
	}

	return true
}

// negative returns a set of coins with all amount negative.
//
// TODO: Remove once unsigned integers are used.
func (coins Coins) negative() Coins {
	res := make([]Coin, 0, len(coins))

	for _, coin := range coins {
		res = append(res, Coin{
			Denom:  coin.Denom,
			Amount: coin.Amount.Neg(),
		})
	}

	return res
}

// removeZeroCoins removes all zero coins from the given coin set in-place.
func removeZeroCoins(coins Coins) Coins {
	i, l := 0, len(coins)
	for i < l {
		if coins[i].IsZero() {
			// remove coin
			coins = append(coins[:i], coins[i+1:]...)
			l--
		} else {
			i++
		}
	}

	return coins[:i]
}

//-----------------------------------------------------------------------------
// Sort interface

//nolint
func (coins Coins) Len() int           { return len(coins) }
func (coins Coins) Less(i, j int) bool { return coins[i].Denom < coins[j].Denom }
func (coins Coins) Swap(i, j int)      { coins[i], coins[j] = coins[j], coins[i] }

var _ sort.Interface = Coins{}

// Sort is a helper function to sort the set of coins inplace
func (coins Coins) Sort() Coins {
	sort.Sort(coins)
	return coins
}

//-----------------------------------------------------------------------------
// Parsing

var (
	// Denominations can be 3 ~ 16 characters long.
	reDnm  = `[[:alpha:]][[:alnum:]]{2,15}`
	reAmt  = `[[:digit:]]+`
	reSpc  = `[[:space:]]*`
	reCoin = regexp.MustCompile(fmt.Sprintf(`^(%s)%s(%s)$`, reAmt, reSpc, reDnm))
)

// ParseCoin parses a cli input for one coin type, returning errors if invalid.
// This returns an error on an empty string as well.
func ParseCoin(coinStr string) (coin Coin, err error) {
	coinStr = strings.TrimSpace(coinStr)

	matches := reCoin.FindStringSubmatch(coinStr)
	if matches == nil {
		return Coin{}, fmt.Errorf("invalid coin expression: %s", coinStr)
	}

	denomStr, amountStr := matches[2], matches[1]

	amount, ok := NewIntFromString(amountStr)
	if !ok {
		return Coin{}, fmt.Errorf("failed to parse coin amount: %s", amountStr)
	}

	return Coin{denomStr, amount}, nil
}
func NewIntFromString(s string) (res Int, ok bool) {
	i, ok := newIntegerFromString(s)
	if !ok {
		return
	}
	// Check overflow
	if i.BitLen() > 255 {
		ok = false
		return
	}
	return Int{i}, true
}
func newIntegerFromString(s string) (*big.Int, bool) {
	return new(big.Int).SetString(s, 0)
}

func (i Int) Neg() (res Int) {
	return Int{neg(i.i)}
}

func neg(i *big.Int) *big.Int { return new(big.Int).Neg(i) }

func gt(i *big.Int, i2 *big.Int) bool { return i.Cmp(i2) == 1 }

func mul(i *big.Int, i2 *big.Int) *big.Int { return new(big.Int).Mul(i, i2) }

func div(i *big.Int, i2 *big.Int) *big.Int { return new(big.Int).Div(i, i2) }

func mod(i *big.Int, i2 *big.Int) *big.Int { return new(big.Int).Mod(i, i2) }

func random(i *big.Int) *big.Int { return new(big.Int).Rand(rand.New(rand.NewSource(rand.Int63())), i) }

func min(i *big.Int, i2 *big.Int) *big.Int {
	if i.Cmp(i2) == 1 {
		return new(big.Int).Set(i2)
	}
	return new(big.Int).Set(i)
}

// MarshalAmino for custom encoding scheme
func marshalAmino(i *big.Int) (string, error) {
	bz, err := i.MarshalText()
	return string(bz), err
}

// UnmarshalAmino for custom decoding scheme
func unmarshalAmino(i *big.Int, text string) (err error) {
	return i.UnmarshalText([]byte(text))
}

// MarshalJSON for custom encoding scheme
// Must be encoded as a string for JSON precision
func marshalJSON(i *big.Int) ([]byte, error) {
	text, err := i.MarshalText()
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(text))
}

// UnmarshalJSON for custom decoding scheme
// Must be encoded as a string for JSON precision
func unmarshalJSON(i *big.Int, bz []byte) error {
	var text string
	err := json.Unmarshal(bz, &text)
	if err != nil {
		return err
	}
	return i.UnmarshalText([]byte(text))
}

// Int wraps integer with 256 bit range bound
// Checks overflow, underflow and division by zero
// Exists in range from -(2^255-1) to 2^255-1

// BigInt converts Int to big.Int
func (i Int) BigInt() *big.Int {
	return new(big.Int).Set(i.i)
}

// NewInt constructs Int from int64

// NewIntFromBigInt constructs Int from big.Int
func NewIntFromBigInt(i *big.Int) Int {
	if i.BitLen() > 255 {
		panic("NewIntFromBigInt() out of bound")
	}
	return Int{i}
}

// NewIntWithDecimal constructs Int with decimal
// Result value is n*10^dec
func NewIntWithDecimal(n int64, dec int) Int {
	if dec < 0 {
		panic("NewIntWithDecimal() decimal is negative")
	}
	exp := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(dec)), nil)
	i := new(big.Int)
	i.Mul(big.NewInt(n), exp)

	// Check overflow
	if i.BitLen() > 255 {
		panic("NewIntWithDecimal() out of bound")
	}
	return Int{i}
}

// OneInt returns Int value with one
func OneInt() Int { return Int{big.NewInt(1)} }

// Int64 converts Int to int64
// Panics if the value is out of range
func (i Int) Int64() int64 {
	if !i.i.IsInt64() {
		panic("Int64() out of bound")
	}
	return i.i.Int64()
}

// IsInt64 returns true if Int64() not panics
func (i Int) IsInt64() bool {
	return i.i.IsInt64()
}

//

// GT returns true if first Int is greater than second
func (i Int) GT(i2 Int) bool {
	return gt(i.i, i2.i)
}

// AddRaw adds int64 to Int
func (i Int) AddRaw(i2 int64) Int {
	return i.Add(NewInt(i2))
}

// SubRaw subtracts int64 from Int
func (i Int) SubRaw(i2 int64) Int {
	return i.Sub(NewInt(i2))
}

// Mul multiples two Ints
func (i Int) Mul(i2 Int) (res Int) {
	// Check overflow
	if i.i.BitLen()+i2.i.BitLen()-1 > 255 {
		panic("Int overflow")
	}
	res = Int{mul(i.i, i2.i)}
	// Check overflow if sign of both are same
	if res.i.BitLen() > 255 {
		panic("Int overflow")
	}
	return
}

// MulRaw multipies Int and int64
func (i Int) MulRaw(i2 int64) Int {
	return i.Mul(NewInt(i2))
}

// Div divides Int with Int
func (i Int) Div(i2 Int) (res Int) {
	// Check division-by-zero
	if i2.i.Sign() == 0 {
		panic("Division by zero")
	}
	return Int{div(i.i, i2.i)}
}

// DivRaw divides Int with int64
func (i Int) DivRaw(i2 int64) Int {
	return i.Div(NewInt(i2))
}

// Mod returns remainder after dividing with Int
func (i Int) Mod(i2 Int) Int {
	if i2.Sign() == 0 {
		panic("division-by-zero")
	}
	return Int{mod(i.i, i2.i)}
}

// ModRaw returns remainder after dividing with int64
func (i Int) ModRaw(i2 int64) Int {
	return i.Mod(NewInt(i2))
}

// Return the minimum of the ints
func MinInt(i1, i2 Int) Int {
	return Int{min(i1.BigInt(), i2.BigInt())}
}

// Human readable string
func (i Int) String() string {
	return i.i.String()
}

// Testing purpose random Int generator
func randomInt(i Int) Int {
	return NewIntFromBigInt(random(i.BigInt()))
}

// MarshalAmino defines custom encoding scheme
func (i Int) MarshalAmino() (string, error) {
	if i.i == nil { // Necessary since default Uint initialization has i.i as nil
		i.i = new(big.Int)
	}
	return marshalAmino(i.i)
}

// UnmarshalAmino defines custom decoding scheme
func (i *Int) UnmarshalAmino(text string) error {
	if i.i == nil { // Necessary since default Int initialization has i.i as nil
		i.i = new(big.Int)
	}
	return unmarshalAmino(i.i, text)
}

// MarshalJSON defines custom encoding scheme
func (i Int) MarshalJSON() ([]byte, error) {
	if i.i == nil { // Necessary since default Uint initialization has i.i as nil
		i.i = new(big.Int)
	}
	return marshalJSON(i.i)
}

// UnmarshalJSON defines custom decoding scheme
func (i *Int) UnmarshalJSON(bz []byte) error {
	if i.i == nil { // Necessary since default Int initialization has i.i as nil
		i.i = new(big.Int)
	}
	return unmarshalJSON(i.i, bz)
}

// Int wraps integer with 256 bit range bound
// Checks overflow, underflow and division by zero
// Exists in range from 0 to 2^256-1
type Uint struct {
	i *big.Int
}

// BigInt converts Uint to big.Unt
func (i Uint) BigInt() *big.Int {
	return new(big.Int).Set(i.i)
}

// NewUint constructs Uint from int64
func NewUint(n uint64) Uint {
	i := new(big.Int)
	i.SetUint64(n)
	return Uint{i}
}

// NewUintFromBigUint constructs Uint from big.Uint
func NewUintFromBigInt(i *big.Int) Uint {
	res := Uint{i}
	if UintOverflow(res) {
		panic("Uint overflow")
	}
	return res
}

// NewUintFromString constructs Uint from string
func NewUintFromString(s string) (res Uint, ok bool) {
	i, ok := newIntegerFromString(s)
	if !ok {
		return
	}
	// Check overflow
	if i.Sign() == -1 || i.Sign() == 1 && i.BitLen() > 256 {
		ok = false
		return
	}
	return Uint{i}, true
}

// NewUintWithDecimal constructs Uint with decimal
// Result value is n*10^dec
func NewUintWithDecimal(n uint64, dec int) Uint {
	if dec < 0 {
		panic("NewUintWithDecimal() decimal is negative")
	}
	exp := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(dec)), nil)
	i := new(big.Int)
	i.Mul(new(big.Int).SetUint64(n), exp)

	res := Uint{i}
	if UintOverflow(res) {
		panic("NewUintWithDecimal() out of bound")
	}

	return res
}

// ZeroUint returns Uint value with zero
func ZeroUint() Uint { return Uint{big.NewInt(0)} }

// OneUint returns Uint value with one
func OneUint() Uint { return Uint{big.NewInt(1)} }

// Uint64 converts Uint to uint64
// Panics if the value is out of range
func (i Uint) Uint64() uint64 {
	if !i.i.IsUint64() {
		panic("Uint64() out of bound")
	}
	return i.i.Uint64()
}

// IsUint64 returns true if Uint64() not panics
func (i Uint) IsUint64() bool {
	return i.i.IsUint64()
}

// IsZero returns true if Uint is zero
func (i Uint) IsZero() bool {
	return i.i.Sign() == 0
}

// Sign returns sign of Uint
func (i Uint) Sign() int {
	return i.i.Sign()
}

// Equal compares two Uints
func (i Uint) Equal(i2 Uint) bool {
	return equal(i.i, i2.i)
}

// GT returns true if first Uint is greater than second
func (i Uint) GT(i2 Uint) bool {
	return gt(i.i, i2.i)
}

// LT returns true if first Uint is lesser than second
func (i Uint) LT(i2 Uint) bool {
	return lt(i.i, i2.i)
}

// Add adds Uint from another
func (i Uint) Add(i2 Uint) (res Uint) {
	res = Uint{add(i.i, i2.i)}
	if UintOverflow(res) {
		panic("Uint overflow")
	}
	return
}

// AddRaw adds uint64 to Uint
func (i Uint) AddRaw(i2 uint64) Uint {
	return i.Add(NewUint(i2))
}

// Sub subtracts Uint from another
func (i Uint) Sub(i2 Uint) (res Uint) {
	res = Uint{sub(i.i, i2.i)}
	if UintOverflow(res) {
		panic("Uint overflow")
	}
	return
}

// SafeSub attempts to subtract one Uint from another. A boolean is also returned
// indicating if the result contains integer overflow.
func (i Uint) SafeSub(i2 Uint) (Uint, bool) {
	res := Uint{sub(i.i, i2.i)}
	if UintOverflow(res) {
		return res, true
	}

	return res, false
}

// SubRaw subtracts uint64 from Uint
func (i Uint) SubRaw(i2 uint64) Uint {
	return i.Sub(NewUint(i2))
}

// Mul multiples two Uints
func (i Uint) Mul(i2 Uint) (res Uint) {
	if i.i.BitLen()+i2.i.BitLen()-1 > 256 {
		panic("Uint overflow")
	}

	res = Uint{mul(i.i, i2.i)}
	if UintOverflow(res) {
		panic("Uint overflow")
	}

	return
}

// MulRaw multipies Uint and uint64
func (i Uint) MulRaw(i2 uint64) Uint {
	return i.Mul(NewUint(i2))
}

// Div divides Uint with Uint
func (i Uint) Div(i2 Uint) (res Uint) {
	// Check division-by-zero
	if i2.Sign() == 0 {
		panic("division-by-zero")
	}
	return Uint{div(i.i, i2.i)}
}

// Div divides Uint with uint64
func (i Uint) DivRaw(i2 uint64) Uint {
	return i.Div(NewUint(i2))
}

// Mod returns remainder after dividing with Uint
func (i Uint) Mod(i2 Uint) Uint {
	if i2.Sign() == 0 {
		panic("division-by-zero")
	}
	return Uint{mod(i.i, i2.i)}
}

// ModRaw returns remainder after dividing with uint64
func (i Uint) ModRaw(i2 uint64) Uint {
	return i.Mod(NewUint(i2))
}

// Return the minimum of the Uints
func MinUint(i1, i2 Uint) Uint {
	return Uint{min(i1.BigInt(), i2.BigInt())}
}

// Human readable string
func (i Uint) String() string {
	return i.i.String()
}

// Testing purpose random Uint generator
func randomUint(i Uint) Uint {
	return NewUintFromBigInt(random(i.BigInt()))
}

// MarshalAmino defines custom encoding scheme
func (i Uint) MarshalAmino() (string, error) {
	if i.i == nil { // Necessary since default Uint initialization has i.i as nil
		i.i = new(big.Int)
	}
	return marshalAmino(i.i)
}

// UnmarshalAmino defines custom decoding scheme
func (i *Uint) UnmarshalAmino(text string) error {
	if i.i == nil { // Necessary since default Uint initialization has i.i as nil
		i.i = new(big.Int)
	}
	return unmarshalAmino(i.i, text)
}

// MarshalJSON defines custom encoding scheme
func (i Uint) MarshalJSON() ([]byte, error) {
	if i.i == nil { // Necessary since default Uint initialization has i.i as nil
		i.i = new(big.Int)
	}
	return marshalJSON(i.i)
}

// UnmarshalJSON defines custom decoding scheme
func (i *Uint) UnmarshalJSON(bz []byte) error {
	if i.i == nil { // Necessary since default Uint initialization has i.i as nil
		i.i = new(big.Int)
	}
	return unmarshalJSON(i.i, bz)
}

//__________________________________________________________________________

// UintOverflow returns true if a given unsigned integer overflows and false
// otherwise.
func UintOverflow(x Uint) bool {
	return x.i.Sign() == -1 || x.i.Sign() == 1 && x.i.BitLen() > 256
}

// AddUint64Overflow performs the addition operation on two uint64 integers and
// returns a boolean on whether or not the result overflows.
func AddUint64Overflow(a, b uint64) (uint64, bool) {
	if math.MaxUint64-a < b {
		return 0, true
	}

	return a + b, false
}

// intended to be used with require/assert:  require.True(IntEq(...))
func IntEq(t *testing.T, exp, got Int) (*testing.T, bool, string, string, string) {
	return t, exp.Equal(got), "expected:\t%v\ngot:\t\t%v", exp.String(), got.String()
}
