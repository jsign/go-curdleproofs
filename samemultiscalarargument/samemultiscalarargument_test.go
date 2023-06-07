package samemultiscalarargument

import (
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/msmaccumulator"
	"github.com/jsign/curdleproofs/transcript"
	"github.com/stretchr/testify/require"
)

func TestSameMultiscalarArgument(t *testing.T) {
	t.Parallel()

	n := 128
	rand, err := common.NewRand(0)
	require.NoError(t, err)

	var proof Proof
	{
		transcriptProver := transcript.New([]byte("same_msm"))

		crs_G_vec, err := rand.GetG1Affines(n)
		require.NoError(t, err)
		Ts, err := rand.GetG1Affines(n)
		require.NoError(t, err)
		Us, err := rand.GetG1Affines(n)
		require.NoError(t, err)
		xs, err := rand.GetFrs(n)
		require.NoError(t, err)

		A, err := (&bls12381.G1Jac{}).MultiExp(crs_G_vec, xs, common.MultiExpConf)
		require.NoError(t, err)
		Z_t, err := (&bls12381.G1Jac{}).MultiExp(Ts, xs, common.MultiExpConf)
		require.NoError(t, err)
		Z_u, err := (&bls12381.G1Jac{}).MultiExp(Us, xs, common.MultiExpConf)
		require.NoError(t, err)

		proof, err = Prove(
			crs_G_vec,
			A,
			Z_t,
			Z_u,
			Ts,
			Us,
			xs,
			transcriptProver,
			rand,
		)
		require.NoError(t, err)
	}

	{
		rando, err := common.NewRand(0)
		require.NoError(t, err)

		transcriptVerifier := transcript.New([]byte("same_msm"))

		crs_G_vec, err := rando.GetG1Affines(n)
		require.NoError(t, err)
		vec_T, err := rando.GetG1Affines(n)
		require.NoError(t, err)
		vec_U, err := rando.GetG1Affines(n)
		require.NoError(t, err)
		vec_x, err := rando.GetFrs(n)
		require.NoError(t, err)

		A, err := (&bls12381.G1Jac{}).MultiExp(crs_G_vec, vec_x, common.MultiExpConf)
		require.NoError(t, err)
		Z_t, err := (&bls12381.G1Jac{}).MultiExp(vec_T, vec_x, common.MultiExpConf)
		require.NoError(t, err)
		Z_u, err := (&bls12381.G1Jac{}).MultiExp(vec_U, vec_x, common.MultiExpConf)
		require.NoError(t, err)

		msmAccumulator := msmaccumulator.New()

		ok, err := Verify(
			&proof,
			crs_G_vec,
			A,
			Z_t,
			Z_u,
			vec_T,
			vec_U,
			transcriptVerifier,
			msmAccumulator,
			rand,
		)
		require.NoError(t, err)
		require.True(t, ok)

		ok, err = msmAccumulator.Verify()
		require.NoError(t, err)
		require.True(t, ok)
	}
}
