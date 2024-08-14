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
	tlDef := "testUser intT:int strT:string bigIntT:int256 bigIntBT:int256 doubleT:double boolT:bool bytesT:bytes = TestUser"
	expectedTypes := []string{"int", "string", "int256", "int256", "double", "bool", "bytes"}
	result := extractTypes(tlDef)

	if len(result) != len(expectedTypes) {
		t.Fatal("length differs")
	}

	for i := 0; i < len(result); i++ {
		if result[i] != expectedTypes[i] {
			t.Fatalf("differs on index: %d", i)
		}
	}
}
