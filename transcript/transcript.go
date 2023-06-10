package transcript

import (
	"bytes"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	transcript "github.com/jsign/merlin"
)

type Transcript struct {
	inner transcript.Transcript
}

func New(label []byte) *Transcript {
	return &Transcript{
		inner: *transcript.New(label),
	}
}

func (t *Transcript) appendMessage(label []byte, message []byte) {
	t.inner.AppendMessage(label, message)
}

// TODO(jsign): maybe unify with AppendPoints since it's variadic.
func (t *Transcript) AppendPoint(label []byte, point *bls12381.G1Affine) {
	var bytes bytes.Buffer
	affineBytes := point.Bytes()
	bytes.Write(affineBytes[:])
	t.appendMessage(label, bytes.Bytes())
}

func (t *Transcript) AppendPoints(label []byte, points ...*bls12381.G1Jac) {
	for _, point := range points {
		var affine bls12381.G1Affine
		affine.FromJacobian(point)
		t.AppendPoint(label, &affine)
	}
}

func (t *Transcript) AppendPointsAffine(label []byte, points ...bls12381.G1Affine) {
	for _, point := range points {
		t.AppendPoint(label, &point)
	}
}

func (t *Transcript) AppendScalars(label []byte, scalars ...fr.Element) {
	for _, scalar := range scalars {
		scalarBytes := scalar.Bytes()
		t.appendMessage([]byte(label), scalarBytes[:])
	}
}

func (t *Transcript) GetAndAppendChallenge(label []byte) fr.Element {
	for {
		var dest [32]byte
		t.inner.ChallengeBytes(label, dest[:])
		var challenge fr.Element
		if err := challenge.SetBytesCanonical(dest[:]); err == nil {
			t.AppendScalars(label, challenge)
			return challenge
		}
	}
}
