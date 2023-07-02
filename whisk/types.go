package whisk

import (
	"bytes"
	"fmt"
	"io"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	curdleproof "github.com/jsign/curdleproofs"
	"github.com/jsign/curdleproofs/common"
)

const (
	G1POINT_SIZE                 = 48
	WHISK_MAX_SHUFFLE_PROOF_SIZE = 1 << 15
	WHISK_MAX_OPENING_PROOF_SIZE = 1 << 10
	TRACKER_PROOF_SIZE           = 128
	N                            = 128
	ELL                          = N - common.N_BLINDERS
)

type G1PointBytes [G1POINT_SIZE]byte

type WhiskShuffleProof struct {
	M     bls12381.G1Jac
	Proof curdleproof.Proof
}

func (wsp *WhiskShuffleProof) FromReader(r io.Reader) error {
	// TODO(jsign): revisit since "decoder" for single element is overkill
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
	rg  G1PointBytes
	krg G1PointBytes
}

func NewWhiskTracker(R_G, K_RG bls12381.G1Affine) WhiskTracker {
	return WhiskTracker{
		rg:  R_G.Bytes(),
		krg: K_RG.Bytes(),
	}
}

func (wt *WhiskTracker) getPoints() (bls12381.G1Affine, bls12381.G1Affine) {
	var R_G bls12381.G1Affine
	var K_RG bls12381.G1Affine
	R_G.Unmarshal(wt.rg[:])
	K_RG.Unmarshal(wt.krg[:])
	return R_G, K_RG
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

type TrackerProof struct {
	A bls12381.G1Jac
	B bls12381.G1Jac
	s fr.Element
}

func (tp *TrackerProof) FromBytes(buf []byte) error {
	if len(buf) != TRACKER_PROOF_SIZE {
		return fmt.Errorf("invalid tracker proof size")
	}
	d := bls12381.NewDecoder(bytes.NewReader(buf))
	if err := d.Decode(&tp.A); err != nil {
		return fmt.Errorf("failed to decode A: %v", err)
	}
	if err := d.Decode(&tp.B); err != nil {
		return fmt.Errorf("failed to decode B: %v", err)
	}
	if err := d.Decode(&tp.s); err != nil {
		return fmt.Errorf("failed to decode s: %v", err)
	}
	return nil
}
