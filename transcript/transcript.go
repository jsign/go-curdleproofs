package transcript

import (
	"bytes"
	"encoding/binary"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/mimoo/StrobeGo/strobe"
)

type Transcript struct {
	strobe strobe.Strobe
}

func New(label []byte) *Transcript {
	return &Transcript{
		strobe: strobe.InitStrobe("", 128),
	}
}

func (t *Transcript) AppendMessage(label []byte, message []byte) {
	var dataLenBytes [4]byte
	binary.LittleEndian.PutUint32(dataLenBytes[:], uint32(len(message)))
	t.strobe.AD(true, label)
	t.strobe.AD(true, dataLenBytes[:])
	t.strobe.AD(false, message)
}

func (t *Transcript) AppendPoint(label []byte, point bls12381.G1Jac) {
	var bytes bytes.Buffer
	var affine bls12381.G1Affine
	affine.FromJacobian(&point)
	affineBytes := affine.Bytes()
	bytes.Write(affineBytes[:])
	t.AppendMessage(label, bytes.Bytes())
}

func (t *Transcript) AppendPoints(label []byte, points []bls12381.G1Jac) {
	for _, point := range points {
		t.AppendPoint(label, point)
	}
}

func (t *Transcript) AppendScalar(label []byte, scalar fr.Element) {
	scalarBytes := scalar.Bytes()
	t.AppendMessage([]byte(label), scalarBytes[:])
}

func (t *Transcript) GetChallenge(label []byte) fr.Element {
	for {
		buf := t.challengeBytes(label, 64)
		var challenge fr.Element
		if err := challenge.SetBytesCanonical(buf); err == nil {
			t.AppendScalar(label, challenge)
		}
	}
}

func (t *Transcript) challengeBytes(label []byte, size uint32) []byte {
	var dataLenBytes [4]byte
	binary.LittleEndian.PutUint32(dataLenBytes[:], size)
	t.strobe.AD(true, label)
	t.strobe.AD(true, dataLenBytes[:])
	return t.strobe.PRF(int(size))

}
