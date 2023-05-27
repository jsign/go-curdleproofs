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
