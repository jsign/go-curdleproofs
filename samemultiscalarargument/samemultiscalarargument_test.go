package samemultiscalarargument

import (
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/msmaccumulator"
	"github.com/jsign/curdleproofs/transcript"
	"github.com/stretchr/testify/require"
)

func TestSameMultiscalarArgument(t *testing.T) {
	t.Parallel()

	n := 128
	var proof Proof
	{
		transcript := transcript.New([]byte("same_msm"))
		rand, err := common.NewRand(42)
		require.NoError(t, err)

		crs_Gs, A, Z_t, Z_u, Ts, Us, xs := setup(t, n)

		proof, err = Prove(
			crs_Gs,
			A,
			Z_t,
			Z_u,
			Ts,
			Us,
			xs,
			transcript,
			rand,
		)
		require.NoError(t, err)
	}

	{
		transcriptVerifier := transcript.New([]byte("same_msm"))
		rand, err := common.NewRand(43)
		require.NoError(t, err)

		crs_Gs, A, Z_t, Z_u, Ts, Us, _ := setup(t, n)
		msmAccumulator := msmaccumulator.New()

		ok, err := Verify(
			proof,
			crs_Gs,
			A,
			Z_t,
			Z_u,
			Ts,
			Us,
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

func setup(t *testing.T, n int) ([]bls12381.G1Affine, bls12381.G1Jac, bls12381.G1Jac, bls12381.G1Jac, []bls12381.G1Affine, []bls12381.G1Affine, []fr.Element) {
	rand, err := common.NewRand(0)
	require.NoError(t, err)

	crs_Gs, err := rand.GetG1Affines(n)
	require.NoError(t, err)
	Ts, err := rand.GetG1Affines(n)
	require.NoError(t, err)
	Us, err := rand.GetG1Affines(n)
	require.NoError(t, err)
	xs, err := rand.GetFrs(n)
	require.NoError(t, err)

	var A, Z_t, Z_u bls12381.G1Jac
	_, err = A.MultiExp(crs_Gs, xs, common.MultiExpConf)
	require.NoError(t, err)
	_, err = Z_t.MultiExp(Ts, xs, common.MultiExpConf)
	require.NoError(t, err)
	_, err = Z_u.MultiExp(Us, xs, common.MultiExpConf)
	require.NoError(t, err)

	return crs_Gs, A, Z_t, Z_u, Ts, Us, xs
}
