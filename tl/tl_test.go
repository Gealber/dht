package tl

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"testing"
)

const (
	testUserTL                     = "testUser intT:int strT:string bigIntT:int256 bigIntBT:int256 boolT:bool bytesT:bytes = TestUser"
	testComplexUserTL              = "testComplexUser intT:int strT:string bigIntT:int256 bigIntBT:int256 boolT:bool bytesT:bytes userData:TestUserData = TestComplexUser"
	testUserDataTL                 = "testUserData name:string lastName:string balance:int lastLogin:long rawData:bytes isBald:bool = TestUserData"
	testPacketContentsTL           = `adnl.packetContents rand1:bytes flags:# from:flags.0?PublicKey from_short:flags.1?adnl.id.short message:flags.2?adnl.Message messages:flags.3?(vector adnl.Message) address:flags.4?adnl.addressList priority_address:flags.5?adnl.addressList seqno:flags.6?long confirm_seqno:flags.7?long recv_addr_list_version:flags.8?int recv_priority_addr_list_version:flags.9?int reinit_date:flags.10?int dst_reinit_date:flags.10?int signature:flags.11?bytes rand2:bytes = adnl.PacketContents`
	testPublicKeyTL                = "pub.ed25519 key:int256 = PublicKey"
	testAdnlIDShortTL              = "adnl.id.short id:int256 = adnl.id.Short"
	testAdnlMessageCreateChannelTL = "adnl.message.createChannel key:int256 date:int = adnl.Message"
	testAdnlMessageQueryTL         = "adnl.message.query query_id:int256 query:bytes = adnl.Message"
	testAdnlAddressUDP             = "adnl.address.udp ip:int port:int = adnl.Address"
	testAdnlAddressListTL          = "adnl.addressList addrs:(vector adnl.Address) version:int reinit_date:int priority:int expire_at:int = adnl.AddressList"
)

func TestSerialize(t *testing.T) {
	s := New()
	tcs := genSerializeTCs()
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.depTlDefs) > 0 {
				s.Register(tc.depTlDefs)
			}

			// registering tl scheme
			s.Register([]ModelRegister{tc.tlDef})
			data, err := s.Serialize(tc.obj, tc.boxed)
			if err != nil {
				t.Fatal(err)
			}

			dataHex := hex.EncodeToString(data)
			if dataHex != tc.expectedDataHex {
				t.Fatal(fmt.Errorf("unexpected data serialization, want: %s got: %s", tc.expectedDataHex, dataHex))
			}
		})
	}
}

func TestParse(t *testing.T) {
	s := New()
	tcs := genParseTCs()
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.depTlDefs) > 0 {
				s.Register(tc.depTlDefs)
			}

			// registering tl scheme
			s.Register([]ModelRegister{tc.tlDef})
			data, err := hex.DecodeString(tc.dataStr)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Parse(data, &tc.obj, tc.boxed)
			if err != nil {
				t.Fatal(err)
			}

			if reflect.DeepEqual(tc.obj, tc.expectedObj) {
				t.Fatal(errors.New("expected object differs from got"))
			}
		})
	}
}

func TestNesstedParse(t *testing.T) {
	s := New()
	tcs := genNestedParseTCs()
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.depTlDefs) > 0 {
				s.Register(tc.depTlDefs)
			}

			// registering tl scheme
			s.Register([]ModelRegister{tc.tlDef})
			data, err := hex.DecodeString(tc.dataStr)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Parse(data, &tc.obj, tc.boxed)
			if err != nil {
				t.Fatal(err)
			}

			if reflect.DeepEqual(tc.obj, tc.expectedObj) {
				t.Fatal(errors.New("expected object differs from got"))
			}

		})
	}
}

func TestParseWithOptional(t *testing.T) {
	s := New()
	tcs := genOptionalParseTCs()
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.depTlDefs) > 0 {
				s.Register(tc.depTlDefs)
			}

			// registering tl scheme
			s.Register([]ModelRegister{tc.tlDef})
			data, err := hex.DecodeString(tc.dataStr)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Parse(data, &tc.obj, tc.boxed)
			if err != nil {
				t.Fatal(err)
			}

			if reflect.DeepEqual(tc.obj, tc.expectedObj) {
				t.Fatal(errors.New("expected object differs from got"))
			}

		})
	}
}

type serializeTestCase struct {
	name            string
	dataStr         string
	obj             any
	boxed           bool
	tlDef           ModelRegister
	depTlDefs       []ModelRegister
	expectedDataHex string
}

type parseSimpleTestCase struct {
	name        string
	boxed       bool
	dataStr     string
	obj         TestUser
	tlDef       ModelRegister
	depTlDefs   []ModelRegister
	expectedObj TestUser
}

type parseComplexTestCase struct {
	name        string
	boxed       bool
	dataStr     string
	obj         TestComplexUser
	tlDef       ModelRegister
	depTlDefs   []ModelRegister
	expectedObj TestComplexUser
}

type parseOptionalTestCase struct {
	name        string
	boxed       bool
	dataStr     string
	obj         TestPacketContents
	tlDef       ModelRegister
	depTlDefs   []ModelRegister
	expectedObj TestPacketContents
}

// TL def: testUser intT:int strT:string bigIntT:int256 bigIntBT:int256 doubleT:double boolT:bool bytesT:bytes = TestUser;
type TestUser struct {
	IntT     int      `tl:"int"`
	StrT     string   `tl:"string"`
	BigIntT  *big.Int `tl:"int256"`
	BigIntBT []byte   `tl:"int256"`
	// DoubleT  float64  `tl:"double"`
	BoolT  bool   `tl:"bool"`
	BytesT []byte `tl:"bytes"`
}

// TL def: testComplexUser intT:int strT:string bigIntT:int256 bigIntBT:int256 doubleT:double boolT:bool bytesT:bytes userData:TestUserData = TestComplexUser;
type TestComplexUser struct {
	IntT     int      `tl:"int"`
	StrT     string   `tl:"string"`
	BigIntT  *big.Int `tl:"int256"`
	BigIntBT []byte   `tl:"int256"`
	// DoubleT  float64  `tl:"double"`
	BoolT    bool         `tl:"bool"`
	BytesT   []byte       `tl:"bytes"`
	UserData TestUserData `tl:"TestUserData"`
}

// TL def: pub.ed25519 key:int256 = PublicKey
type TestPublicKey struct {
	Key []byte `tl:"int256"`
}

// TL def: adnl.id.short id:int256 = adnl.id.Short;
type TestAdnlIDShort struct {
	ID []byte `tl:"int256"`
}

// TL def: adnl.message.createChannel key:int256 date:int = adnl.Message
type TestAdnlMessageCreateChannel struct {
	Key  []byte `tl:"int256"`
	Date int64  `tl:"int"`
}

// TL def: adnl.message.query query_id:int256 query:bytes = adnl.Message
type TestAdnlMessageQuery struct {
	QueryID []byte `tl:"int256"`
	Query   []byte `tl:"bytes"`
}

type TestAdnlMessage interface{}

// TL def: adnl.address.udp ip:int port:int = adnl.Address
type TestAdnlAddressUDP struct {
	IP   int64 `tl:"int"`
	Port int   `tl:"int"`
}

// TL def: adnl.addressList addrs:(vector adnl.Address) version:int reinit_date:int priority:int expire_at:int = adnl.AddressList
type TestAdnlAddressList struct {
	Addresses  []TestAdnlAddressUDP `tl:"vector adnl.Address"`
	Version    int                  `tl:"int"`
	ReinitDate int64                `tl:"int"`
	Priority   int                  `tl:"int"`
	ExpireAt   int                  `tl:"int"`
}

// TL def:
// adnl.packetContents
//
//	rand1:bytes
//	flags:#
//	from:flags.0?PublicKey
//	from_short:flags.1?adnl.id.short
//	message:flags.2?adnl.Message
//	messages:flags.3?(vector adnl.Message)
//	address:flags.4?adnl.addressList
//	priority_address:flags.5?adnl.addressList
//	seqno:flags.6?long
//	confirm_seqno:flags.7?long
//	recv_addr_list_version:flags.8?int
//	recv_priority_addr_list_version:flags.9?int
//	reinit_date:flags.10?int
//	dst_reinit_date:flags.10?int
//	signature:flags.11?bytes
//	rand2:bytes
//	      = adnl.PacketContents;
type TestPacketContents struct {
	Rand1                          []byte                       `tl:"bytes"`
	Flags                          int                          `tl:"flags"`
	From                           TestPublicKey                `tl:"?0 PublicKey"`
	FromShort                      TestAdnlIDShort              `tl:"?1 adnl.id.short"`
	Message                        TestAdnlMessageCreateChannel `tl:"?2 adnl.Message"`
	Messages                       []TestAdnlMessage            `tl:"?3 vector adnl.Message"`
	Address                        TestAdnlAddressList          `tl:"?4 adnl.addressList"`
	PriorityAddress                TestAdnlAddressList          `tl:"?5 adnl.addressList"`
	Seqno                          int64                        `tl:"?6 long"`
	ConfirmSeqno                   int64                        `tl:"?7 long"`
	RecvAddressListVersion         int                          `tl:"?8 int"`
	RecvPriorityAddressListVersion int                          `tl:"?9 int"`
	ReinitDate                     int64                        `tl:"?10 int"`
	DstReinitDate                  int64                        `tl:"?10 int"`
	Signature                      []byte                       `tl:"?11 bytes"`
	Rand2                          []byte                       `tl:"bytes"`
}

// TL definition: testUserData name:string lastName:string balance:int lastLogin:long rawData:bytes isBald:bool = TestUserData
type TestUserData struct {
	Name      string `tl:"string"`
	LastName  string `tl:"string"`
	Balance   int    `tl:"int"`
	LastLogin int64  `tl:"long"`
	RawData   []byte `tl:"bytes"`
	// In case the user is bald
	IsBald bool `tl:"bool"`
}

func genSerializeTCs() []serializeTestCase {
	rand1, _ := hex.DecodeString("4e0e7dd6d0c5646c204573bc47e567")
	rand2, _ := hex.DecodeString("2b6a8c0509f85da9f3c7e11c86ba22")
	queryID, _ := hex.DecodeString("d7be82afbc80516ebca39784b8e2209886a69601251571444514b7f17fcd8875")
	key, _ := hex.DecodeString("afc46336dd352049b366c7fd3fc1b143a518f0d02d9faef896cb0155488915d6")
	createChannelKey, _ := hex.DecodeString("d59d8e3991be20b54dde8b78b3af18b379a62fa30e64af361c75452f6af019d7")
	query, _ := hex.DecodeString("ed4879a9")

	buff := make([]byte, 32)
	return []serializeTestCase{
		{
			name: "simple case with built-in types, structs represents a user",
			obj: TestUser{
				IntT:     1,
				StrT:     "Hola",
				BigIntT:  big.NewInt(10000),
				BigIntBT: big.NewInt(1000).FillBytes(buff),
				// DoubleT:  1.0,
				BoolT:  true,
				BytesT: []byte("Hola"),
			},
			boxed: true,
			tlDef: ModelRegister{
				T:   TestUser{},
				Def: testUserTL,
			},
			expectedDataHex: "e41a611b0100000004486f6c61000000000000000000000000000000000000000000000000000000000000000000271000000000000000000000000000000000000000000000000000000000000003e8b575729904486f6c61000000",
		},
		{
			name: "struct with custom types inside, structs represents a user",
			obj: TestComplexUser{
				IntT:     1,
				StrT:     "Hola",
				BigIntT:  big.NewInt(10000),
				BigIntBT: big.NewInt(1000).FillBytes(buff),
				// DoubleT:  1.0,
				BoolT:    true,
				BytesT:   []byte("Hola"),
				UserData: TestUserData{},
			},
			tlDef: ModelRegister{
				T:   TestComplexUser{},
				Def: testComplexUserTL,
			},
			depTlDefs: []ModelRegister{
				{
					T:   TestUserData{},
					Def: testUserDataTL,
				},
			},
			boxed:           true,
			expectedDataHex: "ef2149c40100000004486f6c61000000000000000000000000000000000000000000000000000000000000000000271000000000000000000000000000000000000000000000000000000000000003e8b575729904486f6c61000000fea3b64d000000000000000000000000000000000000000000000000379779bc",
		},
		{
			name: "test case with a lot of flags, adnl.packetContents",
			// example from https://docs.ton.org/develop/network/adnl-udp
			obj: TestPacketContents{
				Rand1: rand1,
				Flags: 0x05d9,
				From: TestPublicKey{
					Key: key,
				},
				Messages: []TestAdnlMessage{
					TestAdnlMessageCreateChannel{
						Key:  createChannelKey,
						Date: 0x63875c55,
					},
					TestAdnlMessageQuery{
						QueryID: queryID,
						Query:   query,
					},
				},
				Address: TestAdnlAddressList{
					Version:    0x63875c55,
					ReinitDate: 0x63875c55,
				},
				Seqno:                  1,
				RecvAddressListVersion: 0x63875c55,
				ReinitDate:             0x63875c55,
				Rand2:                  rand2,
			},
			tlDef: ModelRegister{
				T:   TestPacketContents{},
				Def: testPacketContentsTL,
			},
			depTlDefs: []ModelRegister{
				{
					T:   TestPublicKey{},
					Def: testPublicKeyTL,
				},
				{
					T:   TestAdnlIDShort{},
					Def: testAdnlIDShortTL,
				},
				{
					T:   TestAdnlMessageCreateChannel{},
					Def: testAdnlMessageCreateChannelTL,
				},
				{
					T:   TestAdnlAddressList{},
					Def: testAdnlAddressListTL,
				},
				{
					T:   TestAdnlMessageQuery{},
					Def: testAdnlMessageQueryTL,
				},
			},
			boxed:           true,
			expectedDataHex: "89cd42d10f4e0e7dd6d0c5646c204573bc47e567d9050000c6b41348afc46336dd352049b366c7fd3fc1b143a518f0d02d9faef896cb0155488915d602000000bbc373e6d59d8e3991be20b54dde8b78b3af18b379a62fa30e64af361c75452f6af019d7555c87637af98bb4d7be82afbc80516ebca39784b8e2209886a69601251571444514b7f17fcd887504ed4879a900000000000000555c8763555c8763000000000000000001000000000000000000000000000000555c8763555c8763000000000f2b6a8c0509f85da9f3c7e11c86ba22",
		},
	}
}

func genParseTCs() []parseSimpleTestCase {
	buff := make([]byte, 32)
	return []parseSimpleTestCase{
		{
			name:    "simple case with built-in types, structs represents a user",
			dataStr: "e41a611b0100000004486f6c61000000000000000000000000000000000000000000000000000000000000000000271000000000000000000000000000000000000000000000000000000000000003e8b575729904486f6c61000000",
			obj:     TestUser{},
			tlDef: ModelRegister{
				T:   TestUser{},
				Def: testUserTL,
			},
			depTlDefs: []ModelRegister{},
			expectedObj: TestUser{
				IntT:     1,
				StrT:     "Hola",
				BigIntT:  big.NewInt(10000),
				BigIntBT: big.NewInt(1000).FillBytes(buff),
				// DoubleT:  1.0,
				BoolT:  true,
				BytesT: []byte("Hola"),
			},
			boxed: true,
		},
	}
}

func genNestedParseTCs() []parseComplexTestCase {
	buff := make([]byte, 32)
	return []parseComplexTestCase{
		{
			name:    "struct with custom types inside, structs represents a user",
			dataStr: "ef2149c40100000004486f6c61000000000000000000000000000000000000000000000000000000000000000000271000000000000000000000000000000000000000000000000000000000000003e8b575729904486f6c61000000fea3b64d000000000000000000000000000000000000000000000000379779bc",
			obj:     TestComplexUser{},
			tlDef: ModelRegister{
				T:   TestComplexUser{},
				Def: testComplexUserTL,
			},
			depTlDefs: []ModelRegister{
				{
					T:   TestUserData{},
					Def: testUserDataTL,
				},
			},
			expectedObj: TestComplexUser{
				IntT:     1,
				StrT:     "Hola",
				BigIntT:  big.NewInt(10000),
				BigIntBT: big.NewInt(1000).FillBytes(buff),
				// DoubleT:  1.0,
				BoolT:    true,
				BytesT:   []byte("Hola"),
				UserData: TestUserData{},
			},
			boxed: true,
		},
	}
}

func genOptionalParseTCs() []parseOptionalTestCase {
	rand1, _ := hex.DecodeString("4e0e7dd6d0c5646c204573bc47e567")
	rand2, _ := hex.DecodeString("2b6a8c0509f85da9f3c7e11c86ba22")
	queryID, _ := hex.DecodeString("d7be82afbc80516ebca39784b8e2209886a69601251571444514b7f17fcd8875")
	key, _ := hex.DecodeString("afc46336dd352049b366c7fd3fc1b143a518f0d02d9faef896cb0155488915d6")
	createChannelKey, _ := hex.DecodeString("d59d8e3991be20b54dde8b78b3af18b379a62fa30e64af361c75452f6af019d7")
	query, _ := hex.DecodeString("ed4879a9")

	return []parseOptionalTestCase{
		{
			name:    "struct with custom types and optional fields",
			dataStr: "89cd42d10f4e0e7dd6d0c5646c204573bc47e567d9050000c6b41348afc46336dd352049b366c7fd3fc1b143a518f0d02d9faef896cb0155488915d602000000bbc373e6d59d8e3991be20b54dde8b78b3af18b379a62fa30e64af361c75452f6af019d7555c87637af98bb4d7be82afbc80516ebca39784b8e2209886a69601251571444514b7f17fcd887504ed4879a900000000000000555c8763555c8763000000000000000001000000000000000000000000000000555c8763555c8763000000000f2b6a8c0509f85da9f3c7e11c86ba22",
			obj:     TestPacketContents{},
			tlDef: ModelRegister{
				T:   TestPacketContents{},
				Def: testPacketContentsTL,
			},
			depTlDefs: []ModelRegister{
				{
					T:   TestPublicKey{},
					Def: testPublicKeyTL,
				},
				{
					T:   TestAdnlIDShort{},
					Def: testAdnlIDShortTL,
				},
				{
					T:   TestAdnlMessageCreateChannel{},
					Def: testAdnlMessageCreateChannelTL,
				},
				{
					T:   TestAdnlAddressList{},
					Def: testAdnlAddressListTL,
				},
				{
					T:   TestAdnlMessageQuery{},
					Def: testAdnlMessageQueryTL,
				},
			},
			expectedObj: TestPacketContents{
				Rand1: rand1,
				Flags: 0x05d9,
				From: TestPublicKey{
					Key: key,
				},
				Messages: []TestAdnlMessage{
					TestAdnlMessageCreateChannel{
						Key:  createChannelKey,
						Date: 0x63875c55,
					},
					TestAdnlMessageQuery{
						QueryID: queryID,
						Query:   query,
					},
				},
				Address: TestAdnlAddressList{
					Version:    0x63875c55,
					ReinitDate: 0x63875c55,
				},
				Seqno:                  1,
				RecvAddressListVersion: 0x63875c55,
				ReinitDate:             0x63875c55,
				Rand2:                  rand2,
			},
			boxed: true,
		},
	}
}
