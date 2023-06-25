package whisk

import bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"

const (
	WHISK_MAX_SHUFFLE_PROOF_SIZE = 1 << 15
	WHISK_MAX_OPENING_PROOF_SIZE = 1 << 10
)

type WhiskShuffleProof struct {
	bytes []byte
}

type WhiskTrackerProof struct {
	bytes []byte
}

type WhiskTracker struct {
	rG   bls12381.G1Jac
	k_rG bls12381.G1Jac
}

type CRS struct {
	Gs   []bls12381.G1Affine
	Hs   []bls12381.G1Affine
	H    bls12381.G1Jac
	Gt   bls12381.G1Jac
	Gu   bls12381.G1Jac
	Gsum bls12381.G1Jac
	Hsum bls12381.G1Jac
}
