package innerproductargument

import bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"

type CRS struct {
	Gs       []bls12381.G1Affine
	Gs_prime []bls12381.G1Affine
	H        bls12381.G1Jac
}
