package whisk

import (
	"bytes"
	"fmt"
	"io"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	curdleproof "github.com/jsign/curdleproofs"
	"github.com/jsign/curdleproofs/common"
)

const (
	WHISK_MAX_SHUFFLE_PROOF_SIZE = 1 << 15
	WHISK_MAX_OPENING_PROOF_SIZE = 1 << 10
	N                            = 128
	ELL                          = N - common.N_BLINDERS
)

type WhiskShuffleProof struct {
	M     bls12381.G1Jac
	Proof curdleproof.Proof
}

func (wsp *WhiskShuffleProof) FromReader(r io.Reader) error {
	d := bls12381.NewDecoder(r)
	if err := d.Decode(&wsp.M); err != nil {
		return fmt.Errorf("failed to decode M: %v", err)
	}
	if err := wsp.Proof.FromReader(r); err != nil {
		return fmt.Errorf("failed to decode proof: %v", err)
	}
	return nil
}

func (wsp *WhiskShuffleProof) Serialize() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, WHISK_MAX_SHUFFLE_PROOF_SIZE))
	e := bls12381.NewEncoder(buf)

	if err := e.Encode(wsp.M); err != nil {
		return nil, fmt.Errorf("failed to encode M: %v", err)
	}
	if err := wsp.Proof.Serialize(buf); err != nil {
		return nil, fmt.Errorf("failed to encode proof: %v", err)
	}

	return buf.Bytes(), nil
}

type WhiskTracker struct {
	R_G  bls12381.G1Affine
	K_RG bls12381.G1Affine
}

func (wt *WhiskTracker) getCoordinates() (bls12381.G1Affine, bls12381.G1Affine) {
	return wt.R_G, wt.K_RG
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
