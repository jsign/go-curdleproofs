package samescalarargument

import (
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/groupcommitment"
	"github.com/jsign/curdleproofs/transcript"
	"github.com/stretchr/testify/require"
)

func TestProveVerify(t *testing.T) {
	t.Parallel()

	rand, err := common.NewRand(0)
	require.NoError(t, err)

	transcriptProver := transcript.New([]byte("same_scalar"))

	var crs CRS
	crs.Gt, err = rand.GetG1Jac()
	require.NoError(t, err)
	crs.Gu, err = rand.GetG1Jac()
	require.NoError(t, err)
	crs.H, err = rand.GetG1Jac()
	require.NoError(t, err)

	R, err := rand.GetG1Jac()
	require.NoError(t, err)
	S, err := rand.GetG1Jac()
	require.NoError(t, err)

	k, err := rand.GetFr()
	require.NoError(t, err)
	r_t, err := rand.GetFr()
	require.NoError(t, err)
	r_u, err := rand.GetFr()
	require.NoError(t, err)

	var tmp bls12381.G1Jac
	T := groupcommitment.New(crs.Gt, crs.H, *tmp.ScalarMultiplication(&R, common.FrToBigInt(&k)), r_t)
	U := groupcommitment.New(crs.Gu, crs.H, *tmp.ScalarMultiplication(&S, common.FrToBigInt(&k)), r_u)

	proof, err := Prove(
		crs,
		R,
		S,
		T,
		U,
		k,
		r_t,
		r_u,
		transcriptProver,
		rand,
	)
	require.NoError(t, err)

	transcriptVerifier := transcript.New([]byte("same_scalar"))
	require.True(t, Verify(
		proof,
		crs,
		R,
		S,
		T,
		U,
		transcriptVerifier,
	))
}
