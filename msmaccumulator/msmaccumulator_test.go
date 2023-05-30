package msmaccumulator

import (
	"strconv"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/jsign/curdleproofs/common"
	"github.com/stretchr/testify/require"
)

func TestMSMAccumulator(t *testing.T) {
	t.Parallel()
	for n := range []int{1, 4, 8, 16} {
		n := n
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			t.Parallel()

			var err error
			rand, err := common.NewRand(0)
			require.NoError(t, err)

			A, err := rand.GetG1Affines(n)
			require.NoError(t, err)
			x, err := rand.GetFrs(n)
			require.NoError(t, err)
			var C1 bls12381.G1Jac
			_, err = C1.MultiExp(A, x, common.MultiExpConf)
			require.NoError(t, err)

			B, err := rand.GetG1Affines(n)
			require.NoError(t, err)
			y, err := rand.GetFrs(n)
			require.NoError(t, err)
			var C2 bls12381.G1Jac
			_, err = C2.MultiExp(B, y, common.MultiExpConf)
			require.NoError(t, err)

			ma := New()
			ma.AccumulateCheck(C1, x, A, rand)
			require.NoError(t, err)
			ma.AccumulateCheck(C2, y, B, rand)
			require.NoError(t, err)

			ok, err := ma.Verify()
			require.NoError(t, err)
			require.True(t, ok)
		})
	}
}
