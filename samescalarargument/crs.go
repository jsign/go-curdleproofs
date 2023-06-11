package samescalarargument

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// TODO(jsign): move to main file.
type CRS struct {
	Gt bls12381.G1Jac
	Gu bls12381.G1Jac
	H  bls12381.G1Jac
}
