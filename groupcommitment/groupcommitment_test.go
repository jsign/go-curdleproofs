package groupcommitment

import (
	"bytes"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecode(t *testing.T) {
	t.Parallel()

	_, _, g1, _ := bls12381.Generators()
	var tmp fr.Element
	var t1 bls12381.G1Affine
	tmp.SetRandom()
	t1.ScalarMultiplication(&g1, common.FrToBigInt(&tmp))
	var t2 bls12381.G1Affine
	tmp.SetRandom()
	t2.ScalarMultiplication(&g1, common.FrToBigInt(&tmp))

	var gc GroupCommitment
	gc.T_1.FromAffine(&t1)
	gc.T_2.FromAffine(&t2)

	buf := bytes.NewBuffer(nil)
	require.NoError(t, gc.Serialize(buf))
	expected := buf.Bytes()

	var gc2 GroupCommitment
	require.NoError(t, gc2.FromReader(buf))

	buf2 := bytes.NewBuffer(nil)
	require.NoError(t, gc2.Serialize(buf2))

	require.Equal(t, expected, buf2.Bytes())
}
