package group

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

type GroupG1 struct {
}

func (g *GroupG1) CreateElement() Element {
	return &G1Element{}
}

// G1Element implements Elemen backed by a G1 element.
type G1Element struct {
	inner bls12381.G1Jac
}

func FromG1Jac(g1Jac bls12381.G1Jac) Element {
	return &G1Element{
		inner: g1Jac,
	}
}

func (z *G1Element) ScalarMultiplication(e Element, scalar *big.Int) Element {
	ee := e.(*G1Element).inner
	z.inner.ScalarMultiplication(&ee, scalar)
	return z
}

func (z *G1Element) Set(e Element) Element {
	ee := e.(*G1Element).inner
	z.inner.Set(&ee)
	return z
}

func (z *G1Element) AddAssign(e Element) Element {
	ee := e.(*G1Element).inner
	z.inner.AddAssign(&ee)
	return z
}

func (z *G1Element) Equal(e Element) bool {
	ee := e.(*G1Element).inner
	return z.inner.Equal(&ee)
}

func (z *G1Element) Bytes() []byte {
	var aff bls12381.G1Affine
	aff.FromJacobian(&z.inner)
	res := aff.Bytes()
	return res[:]
}
