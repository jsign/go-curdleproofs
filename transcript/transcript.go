package transcript

import (
	"bytes"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/group"
	transcript "github.com/jsign/merlin"
)

type Transcript struct {
	inner *transcript.Transcript
}

func New(label []byte) *Transcript {
	return &Transcript{
		inner: transcript.New(label),
	}
}

func (t *Transcript) appendMessage(label []byte, message []byte) {
	t.inner.AppendMessage(label, message)
}

func (t *Transcript) AppendPoints(label []byte, points ...bls12381.G1Jac) {
	affs := bls12381.BatchJacobianToAffineG1(points)
	for _, point := range affs {
		t.AppendPointsAffine(label, point)
	}
}

// TEMP: experimental.
func (t *Transcript) AppendGroupElements(label []byte, points ...group.Element) {
	for _, point := range points {
		var bytes bytes.Buffer
		affineBytes := point.Bytes()
		bytes.Write(affineBytes[:])
		t.appendMessage(label, bytes.Bytes())

	}
}

func (t *Transcript) AppendPointsAffine(label []byte, points ...bls12381.G1Affine) {
	for _, point := range points {
		var bytes bytes.Buffer
		affineBytes := point.Bytes()
		bytes.Write(affineBytes[:])
		t.appendMessage(label, bytes.Bytes())
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

// TEMP: experimental.
func (t *Transcript) GetAndAppendChallengeBigInt(label []byte) big.Int {
	var dest [128]byte
	t.inner.ChallengeBytes(label, dest[:])
	var challenge big.Int
	challenge.SetBytes(dest[:])
	return challenge
}

func (t *Transcript) GetAndAppendChallenges(label []byte, count int) []fr.Element {
	challenges := make([]fr.Element, count)
	for i := 0; i < count; i++ {
		challenges[i] = t.GetAndAppendChallenge(label)
	}
	return challenges
}
