package samescalarargument

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

type CRS struct {
	G_t bls12381.G1Jac
	G_u bls12381.G1Jac
	H   bls12381.G1Jac
}
