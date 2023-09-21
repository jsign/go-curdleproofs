package group

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type Group interface {
	CreateElement() Element
}

type Element interface {
	ScalarMultiplication(e Element, scalar fr.Element) Element
	Set(e Element) Element
	AddAssign(e Element) Element
	Equal(e Element) bool
	Bytes() []byte
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
