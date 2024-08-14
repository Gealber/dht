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
	testUserTL        = "testUser intT:int strT:string bigIntT:int256 bigIntBT:int256 boolT:bool bytesT:bytes = TestUser"
	testComplexUserTL = "testComplexUser intT:int strT:string bigIntT:int256 bigIntBT:int256 boolT:bool bytesT:bytes userData:TestUserData = TestComplexUser"
	testUserDataTL    = "testUserData name:string lastName:string balance:int lastLogin:long rawData:bytes isBald:bool = TestUserData"
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

			n, err := s.Parse(data, &tc.obj, tc.boxed)
			if err != nil {
				t.Fatal(err)
			}

			if reflect.DeepEqual(tc.obj, tc.expectedObj) {
				t.Fatal(errors.New("expected object differs from got"))
			}

			if len(data) != n {
				t.Fatalf("length data and data consumed differs: want: %d got: %d", len(data), n)
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

			n, err := s.Parse(data, &tc.obj, tc.boxed)
			if err != nil {
				t.Fatal(err)
			}

			if reflect.DeepEqual(tc.obj, tc.expectedObj) {
				t.Fatal(errors.New("expected object differs from got"))
			}

			if len(data) != n {
				t.Fatalf("length data and data consumed differs: want: %d got: %d", len(data), n)
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
