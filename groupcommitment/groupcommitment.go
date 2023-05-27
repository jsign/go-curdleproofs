package groupcommitment

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
)

type GroupCommitment struct {
	T_1 bls12381.G1Jac
	T_2 bls12381.G1Jac
}

func New(
	crs_G, crs_H *bls12381.G1Jac,
	T *bls12381.G1Jac,
	r *fr.Element,
) *GroupCommitment {
	var T_1 bls12381.G1Jac
	T_1.ScalarMultiplication(crs_G, common.FrToBigInt(r))

	var T_2 bls12381.G1Jac
	T_2.Set(T)
	T_2.AddAssign((&bls12381.G1Jac{}).ScalarMultiplication(crs_H, common.FrToBigInt(r)))
	return &GroupCommitment{
		T_1: T_1,
		T_2: T_2,
	}
}

func (t *GroupCommitment) Add(cm GroupCommitment) GroupCommitment {
	ret := GroupCommitment{}
	ret.T_1.Set(&t.T_1)
	ret.T_1.AddAssign(&cm.T_1)
	ret.T_2.Set(&t.T_2)
	ret.T_2.AddAssign(&cm.T_2)
	return ret
}

func (t *GroupCommitment) Mul(scalar fr.Element) GroupCommitment {
	bigIntScalar := common.FrToBigInt(&scalar)
	ret := GroupCommitment{}
	ret.T_1.ScalarMultiplication(&t.T_1, bigIntScalar)
	ret.T_2.ScalarMultiplication(&t.T_2, bigIntScalar)
	return ret
}

func (t *GroupCommitment) Eq(cm *GroupCommitment) bool {
	return t.T_1.Equal(&cm.T_1) && t.T_2.Equal(&cm.T_2)
}
