package merkletree

import (
	"fmt"
	"testing"
)

func TestNewTree(t *testing.T) {
	leafsData := []Data{[]byte("toi"), []byte("di"), []byte("hoc"), []byte("them"), []byte("mon"), []byte("vat"), []byte("ly")}
	tree := NewTree(leafsData)
	fmt.Println(tree)
}

func TestTreeVerifyProofs(t *testing.T) {
	leafsData := []Data{[]byte("toi"), []byte("di"), []byte("hoc"), []byte("them"), []byte("mon"), []byte("vat"), []byte("ly")}
	leafData := Data("toi")
	leafData2 := Data("anh")

	tree := NewTree(leafsData)
	proofs, err := tree.GetProofs(leafData.Hash())
	if err != nil {
		t.Fatal(err)
	}

	if !tree.VerifyProofs(proofs, leafData.Hash()) {
		t.Fatal("verify failed")
	}

	if tree.VerifyProofs(proofs, leafData2.Hash()) {
		t.Fatal("verify failed")
	}
}
