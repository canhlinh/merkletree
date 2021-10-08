package merkletree

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
)

type Data []byte
type Hash [32]byte

func (d Data) Hash() Hash {
	return HashData(d)
}

func HashData(data Data) Hash {
	return sha256.Sum256(data)
}

type Node interface {
	Hash() Hash
}

type Leaf struct {
	hash Hash
	data Data
}

func NewLeaf(data Data) *Leaf {
	return &Leaf{
		data: data,
		hash: HashData(data),
	}
}

func (node *Leaf) Hash() Hash {
	return node.hash
}

type Branch struct {
	hash  Hash
	left  Node
	right Node
}

func MergeHash(leftHash Hash, rightHash Hash) Hash {
	combination := []byte{}
	for _, hash := range leftHash {
		combination = append(combination, hash)
	}
	for _, hash := range rightHash {
		combination = append(combination, hash)
	}
	return HashData(combination)
}

func NewBranch(leftNode Node, rightNode Node) *Branch {
	branch := &Branch{
		left:  leftNode,
		right: rightNode,
		hash:  MergeHash(leftNode.Hash(), rightNode.Hash()),
	}
	return branch
}

func (node *Branch) Hash() Hash {
	return node.hash
}

type MerkleTree struct {
	root Node
	rows [][]Node
}

func NewTree(leafsData []Data) *MerkleTree {
	dataLen := len(leafsData)
	depth := int(math.Ceil(math.Log2(float64(dataLen+dataLen%2))) + 1)

	rows := make([][]Node, depth)
	for _, data := range leafsData {
		rows[0] = append(rows[0], NewLeaf(data))
	}

	if (len(leafsData)-1)%2 == 0 {
		// Duplicate the odd leaf
		rows[0] = append(rows[0], rows[0][len(leafsData)-1])
	}

	for i := 1; i < depth; i++ {
		prevNodes := rows[i-1]

		for j := 0; j < len(prevNodes); j = j + 2 {
			var left, right Node

			if j+1 >= len(prevNodes) {
				left = prevNodes[j]
				right = left
			} else {
				left = prevNodes[j]
				right = prevNodes[j+1]
			}

			branchNode := NewBranch(left, right)
			rows[i] = append(rows[i], branchNode)
		}
	}

	return &MerkleTree{
		rows: rows,
		root: rows[depth-1][0],
	}
}

func (tree MerkleTree) String() string {
	if tree.root == nil {
		return "EmptyTree"
	}

	s := ""
	for i := len(tree.rows) - 1; i >= 0; i-- {
		nodes := tree.rows[i]

		for j, node := range nodes {
			switch v := node.(type) {
			case *Leaf:
				s += fmt.Sprintf("%s%d-%d(%s) ", "L", i, j, v.data)
			case *Branch:
				s += fmt.Sprintf("%s%d-%d ", "B", i, j)
			}
		}
		s += "\n"
	}
	return s
}

type Direction string

const (
	Left  Direction = "left"
	Right Direction = "right"
)

type Proof struct {
	direction Direction
	hash      Hash
}

func (tree MerkleTree) getLeafIndex(leafHash Hash) int {
	for i := 0; i < len(tree.rows[0]); i++ {
		if tree.rows[0][i].Hash() == leafHash {
			return i
		}
	}
	return -1
}

func (tree MerkleTree) GetProofs(leafHash Hash) ([]*Proof, error) {
	index := tree.getLeafIndex(leafHash)
	if index == -1 {
		return nil, errors.New("Leaf not found")
	}

	proofs := []*Proof{}
	for i := 0; i < len(tree.rows)-1; i++ {
		if (index % 2) == 1 {
			proofs = append(proofs, &Proof{
				direction: Left,
				hash:      tree.rows[i][index-1].Hash(),
			})
		} else {
			proofs = append(proofs, &Proof{
				direction: Right,
				hash:      tree.rows[i][index+1].Hash(),
			})
		}

		index = int(float64(index / 2))
	}

	return proofs, nil
}

func (tree MerkleTree) VerifyProofs(proofs []*Proof, leafHash Hash) bool {
	index := tree.getLeafIndex(leafHash)
	if index == -1 {
		return false
	}

	branchHash := leafHash
	for _, proof := range proofs {
		if proof.direction == Left {
			branchHash = MergeHash(proof.hash, branchHash)
		} else {
			branchHash = MergeHash(branchHash, proof.hash)
		}
	}

	return branchHash == tree.root.Hash()
}
