package common

import bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"

type GroupCommitment struct {
	T_1 bls12381.G1Jac
	T_2 bls12381.G1Jac
}
