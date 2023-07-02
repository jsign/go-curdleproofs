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
type TrackerProofBytes [TRACKER_PROOF_SIZE]byte

var g1Gen bls12381.G1Affine

func init() {
	_, _, g1Gen, _ = bls12381.Generators()
}

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
	rG  G1PointBytes
	krG G1PointBytes
}

func NewWhiskTracker(rG, krG bls12381.G1Affine) WhiskTracker {
	return WhiskTracker{
		rG:  rG.Bytes(),
		krG: krG.Bytes(),
	}
}

func (wt *WhiskTracker) getPoints() (bls12381.G1Affine, bls12381.G1Affine, error) {
	var rG bls12381.G1Affine
	var krG bls12381.G1Affine
	if _, err := rG.SetBytes(wt.rG[:]); err != nil {
		return bls12381.G1Affine{}, bls12381.G1Affine{}, fmt.Errorf("failed to set rG: %v", err)
	}
	if _, err := krG.SetBytes(wt.krG[:]); err != nil {
		return bls12381.G1Affine{}, bls12381.G1Affine{}, fmt.Errorf("failed to set krG: %v", err)
	}
	return rG, krG, nil
}

type CRS = curdleproof.CRS

type TrackerProof struct {
	A bls12381.G1Affine
	B bls12381.G1Affine
	S fr.Element
}

func (tp *TrackerProof) FromBytes(buf TrackerProofBytes) error {
	d := bls12381.NewDecoder(bytes.NewReader(buf[:]))
	if err := d.Decode(&tp.A); err != nil {
		return fmt.Errorf("failed to decode A: %v", err)
	}
	if err := d.Decode(&tp.B); err != nil {
		return fmt.Errorf("failed to decode B: %v", err)
	}
	if err := d.Decode(&tp.S); err != nil {
		return fmt.Errorf("failed to decode s: %v", err)
	}
	return nil
}

func (tp *TrackerProof) Serialize() TrackerProofBytes {
	// TODO(jsign): avoid alloc.
	var buf bytes.Buffer
	e := bls12381.NewEncoder(&buf)
	// bytes.Buffer, by design, never fails as an io.Writer.
	_ = e.Encode(&tp.A)
	_ = e.Encode(&tp.B)
	_ = e.Encode(&tp.S)
	return TrackerProofBytes(buf.Bytes())
}
