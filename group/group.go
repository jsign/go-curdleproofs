package group

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
)

type Group interface {
	CreateElement() Element
}

type Element interface {
	ScalarMultiplication(e Element, scalar fr.Element) Element
	Set(e Element) Element
	Add(a, b Element) Element
	AddAssign(e Element) Element
	Equal(e Element) bool
	Bytes() []byte
	MultiExp([]Element, []fr.Element) (Element, error)
}

type GroupCommitment struct {
	g Group

	T_1 Element
	T_2 Element
}

func NewGroupCommitment(
	group Group,
	crsG Element,
	crsH Element,
	T Element,
	r fr.Element,
) GroupCommitment {
	T_1, T_2, tmp := group.CreateElement(), group.CreateElement(), group.CreateElement()
	T_1.ScalarMultiplication(crsG, r)
	T_2.Set(T).AddAssign(tmp.ScalarMultiplication(crsH, r))

	return GroupCommitment{
		g:   group,
		T_1: T_1,
		T_2: T_2,
	}
}

func (gc *GroupCommitment) Add(cm GroupCommitment) GroupCommitment {
	ret := GroupCommitment{
		g:   gc.g,
		T_1: gc.g.CreateElement(),
		T_2: gc.g.CreateElement(),
	}
	ret.T_1.Set(gc.T_1).AddAssign(cm.T_1)
	ret.T_2.Set(gc.T_2).AddAssign(cm.T_2)

	return ret
}

func (gc *GroupCommitment) Mul(scalar fr.Element) GroupCommitment {
	ret := GroupCommitment{
		g:   gc.g,
		T_1: gc.g.CreateElement(),
		T_2: gc.g.CreateElement(),
	}
	ret.T_1.ScalarMultiplication(gc.T_1, scalar)
	ret.T_2.ScalarMultiplication(gc.T_2, scalar)

	return ret
}

func (t GroupCommitment) Eq(cm GroupCommitment) bool {
	return t.T_1.Equal(cm.T_1) && t.T_2.Equal(cm.T_2)
}

type MsmAccumulator struct {
	g             Group
	A_c           Element
	baseScalarMap []msmCoeff
}

type msmCoeff struct {
	basis  Element
	scalar fr.Element
}

func NewMsmAccumulator(g Group) *MsmAccumulator {
	return &MsmAccumulator{
		g:             g,
		A_c:           g.CreateElement(),
		baseScalarMap: nil,
	}
}

func (ma *MsmAccumulator) AccumulateCheck(
	C Element,
	scalar []fr.Element,
	basis []Element,
	rand *common.Rand) error {
	if len(basis) != len(scalar) {
		return fmt.Errorf("x and v must have the same length")
	}

	alpha, err := rand.GetFr()
	if err != nil {
		return fmt.Errorf("get random scalar: %s", err)
	}

	var tmp fr.Element
outer:
	for i := 0; i < len(basis); i++ {
		tmp.Mul(&alpha, &scalar[i])

		for j := range ma.baseScalarMap {
			if ma.baseScalarMap[j].basis.Equal(basis[i]) {
				var scalar fr.Element
				scalar.Add(&ma.baseScalarMap[j].scalar, &tmp)
				ma.baseScalarMap[j].scalar = scalar
				continue outer
			}
		}
		ma.baseScalarMap = append(ma.baseScalarMap, msmCoeff{basis: basis[i], scalar: tmp})
	}
	ma.A_c.AddAssign(C.ScalarMultiplication(C, alpha))

	return nil
}

func (ma *MsmAccumulator) Verify() (bool, error) {
	x := make([]fr.Element, 0, len(ma.baseScalarMap))
	v := make([]Element, 0, len(ma.baseScalarMap))

	for _, coeff := range ma.baseScalarMap {
		v = append(v, coeff.basis)
		x = append(x, coeff.scalar)
	}

	msmRes := ma.g.CreateElement()
	if _, err := msmRes.MultiExp(v, x); err != nil {
		return false, fmt.Errorf("computing msm: %s", err)
	}

	return msmRes.Equal(ma.A_c), nil
}
