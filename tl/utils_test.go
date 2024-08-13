package tl

import (
	"fmt"
	"testing"
)

func Test_getCombinator(t *testing.T) {
	tlDef := "overlay.getRandomPeers peers:overlay.nodes = overlay.Nodes"
	if getCombinator(tlDef) != "overlay.Nodes" {
		t.Fatal(fmt.Errorf("want: overlay.Nodes got: %s", getCombinator(tlDef)))
	}
}

func Test_getConstructor(t *testing.T) {
	tlDef := "overlay.getRandomPeers peers:overlay.nodes = overlay.Nodes"
	if getConstructor(tlDef) != "overlay.getRandomPeers" {
		t.Fatal(fmt.Errorf("want: overlay.getRandomPeers got: %s", getConstructor(tlDef)))
	}
}
