package group

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

type GroupGt struct {
}

func (g *GroupGt) CreateElement() Element {
	return &GtElement{}
}

// GtElement implements Elemen backed by a Gt element.
type GtElement struct {
	inner bls12381.GT
}

func (z *GtElement) ScalarMultiplication(e Element, scalar *big.Int) Element {
	panic("TODO")
}

func (z *GtElement) Set(e Element) Element {
	panic("TODO")
}

func (z *GtElement) AddAssign(e Element) Element {
	panic("TODO")
}

func (z *GtElement) Equal(e Element) bool {
	panic("TODO")
}

func (z *GtElement) Bytes() []byte {
	panic("TODO")
}
