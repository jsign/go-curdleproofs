package whisk

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/jsign/curdleproofs/common"
)

const (
	WHISK_MAX_SHUFFLE_PROOF_SIZE = 1 << 15
	WHISK_MAX_OPENING_PROOF_SIZE = 1 << 10
	N                            = 128
	ELL                          = N - common.N_BLINDERS
)

type WhiskShuffleProofBytes []byte

type WhiskTracker struct {
	rG   bls12381.G1Affine
	k_rG bls12381.G1Affine
}

func (wt *WhiskTracker) getCoordinates() (bls12381.G1Affine, bls12381.G1Affine) {
	return wt.rG, wt.k_rG
}

type CRS struct {
	Gs   []bls12381.G1Affine
	Hs   []bls12381.G1Affine
	H    bls12381.G1Jac
	Gt   bls12381.G1Jac
	Gu   bls12381.G1Jac
	Gsum bls12381.G1Affine
	Hsum bls12381.G1Affine
}
