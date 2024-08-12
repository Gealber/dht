package tl

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

func TestSerialize(t *testing.T) {
	s := NewSerializer()
	tcs := genSerializeTCs()
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			// registering tl scheme
			s.Register([]ModelRegister{
				{T: TestUser{}, Def: tc.tlDef},
			})
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

type serializeTestCase struct {
	name            string
	dataStr         string
	obj             any
	boxed           bool
	tlDef           string
	expectedDataHex string
}

type TestUser struct {
	IntT int    `tl:"int"`
	StrT string `tl:"string"`
	// BigIntT  *big.Int `tl:"int256"`
	BigIntBT []byte `tl:"int256"`
	// DoubleT  float64  `tl:"double"`
	BoolT  bool   `tl:"bool"`
	BytesT []byte `tl:"bytes"`
}

func genSerializeTCs() []serializeTestCase {
	buff := make([]byte, 32)
	return []serializeTestCase{
		{
			name: "simple case with built-in types, structs represents a user",
			obj: TestUser{
				IntT: 1,
				StrT: "Hola",
				// BigIntT:  big.NewInt(1),
				BigIntBT: big.NewInt(1).FillBytes(buff),
				// DoubleT:  1.0,
				BoolT:  true,
				BytesT: []byte("Hola"),
			},
			boxed:           true,
			tlDef:           "testUser intT:int strT:string bigIntT:int256 bigIntBT:int256 doubleT:double boolT:bool bytesT:bytes = TestUser;",
			expectedDataHex: "e098a0f30100000004486f6c610000000000000000000000000000000000000000000000000000000000000000000001b575729904486f6c61000000",
		},
	}
}
