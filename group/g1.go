package group

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
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

func (z *G1Element) ScalarMultiplication(e Element, scalar fr.Element) Element {
	ee := e.(*G1Element).inner
	var bi big.Int
	scalar.BigInt(&bi)
	z.inner.ScalarMultiplication(&ee, &bi)
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

func (z *G1Element) SubAssign(e Element) Element {
	ee := e.(*G1Element).inner
	z.inner.SubAssign(&ee)
	return z
}

func (z *G1Element) Add(a, b Element) Element {
	aa := a.(*G1Element).inner
	bb := b.(*G1Element).inner
	z.inner.Set(&aa)
	z.inner.AddAssign(&bb)
	return z
}

func (z *G1Element) Sub(a, b Element) Element {
	aa := a.(*G1Element).inner
	bb := b.(*G1Element).inner
	z.inner.Set(&aa)
	z.inner.SubAssign(&bb)
	return z
}

func (z *G1Element) MultiExp(base []Element, scalars []fr.Element) (Element, error) {
	jacs := make([]bls12381.G1Jac, len(base))
	for i := 0; i < len(base); i++ {
		jacs[i] = base[i].(*G1Element).inner
	}
	affs := bls12381.BatchJacobianToAffineG1(jacs)
	if _, err := z.inner.MultiExp(affs, scalars, common.MultiExpConf); err != nil {
		return nil, fmt.Errorf("g1 multiexp: %s", err)
	}
	return z, nil
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
