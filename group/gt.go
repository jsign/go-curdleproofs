package group

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
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

func FromGt(gt bls12381.GT) Element {
	return &GtElement{
		inner: gt,
	}
}

func (z *GtElement) ScalarMultiplication(e Element, scalar fr.Element) Element {
	ee := e.(*GtElement).inner
	var bi big.Int
	scalar.BigInt(&bi)
	z.inner.ExpGLV(ee, &bi)
	return z
}

func (z *GtElement) Set(e Element) Element {
	ee := e.(*GtElement).inner
	z.inner.Set(&ee)
	return z
}

func (z *GtElement) AddAssign(e Element) Element {
	ee := e.(*GtElement).inner
	z.inner.Mul(&z.inner, &ee)
	return z
}

func (z *GtElement) Equal(e Element) bool {
	ee := e.(*GtElement).inner
	return z.inner.Equal(&ee)
}

func (z *GtElement) Bytes() []byte {
	res := z.inner.Bytes()
	return res[:]
}
