package tl

import (
	"testing"
)

func Test_getCombinator(t *testing.T) {
	tlDef := "overlay.getRandomPeers peers:overlay.nodes = overlay.Nodes"
	if getCombinator(tlDef) != "overlay.Nodes" {
		t.Fatalf("want: overlay.Nodes got: %s", getCombinator(tlDef))
	}
}

func Test_getConstructor(t *testing.T) {
	tlDef := "overlay.getRandomPeers peers:overlay.nodes = overlay.Nodes"
	if getConstructor(tlDef) != "overlay.getRandomPeers" {
		t.Fatalf("want: overlay.getRandomPeers got: %s", getConstructor(tlDef))
	}
}

func Test_extractTypes(t *testing.T) {
	type testCase struct {
		name   string
		tlDef  string
		result []string
	}

	tcs := []testCase{
		{
			name:   "simple case, no flags",
			tlDef:  "testUser intT:int strT:string bigIntT:int256 bigIntBT:int256 doubleT:double boolT:bool bytesT:bytes = TestUser",
			result: []string{"int", "string", "int256", "int256", "double", "bool", "bytes"},
		},
		{

			name:   "case with flags present and vector",
			tlDef:  TLPacketContents,
			result: []string{"bytes", "#", "flags.0?PublicKey", "flags.1?adnl.id.short", "flags.2?adnl.Message", "flags.3?(vector adnl.Message)", "flags.4?adnl.addressList", "flags.5?adnl.addressList", "flags.6?long", "flags.7?long", "flags.8?int", "flags.9?int", "flags.10?int", "flags.10?int", "flags.11?bytes", "bytes"},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			result := extractTypes(tc.tlDef)

			if len(result) != len(tc.result) {
				t.Fatal("length differs")
			}

			for i := 0; i < len(result); i++ {
				if result[i] != tc.result[i] {
					t.Fatalf("differs on index: %d", i)
				}
			}
		})

	}
}

func Test_extractOptionalBitPosition(t *testing.T) {
	tc := "flags.3?PublicKey"
	result := extractOptionalBitPosition(tc)
	if result != 3 {
		t.Fatal("unexpected result")
	}
}
