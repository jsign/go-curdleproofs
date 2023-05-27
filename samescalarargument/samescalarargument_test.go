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
	rand, err := common.NewRand(0)
	require.NoError(t, err)

	// Prove

	transcriptProver := transcript.New([]byte("same_scalar"))

	var crs CRS
	crs.G_t, err = rand.GetG1()
	require.NoError(t, err)
	crs.G_u, err = rand.GetG1()
	require.NoError(t, err)
	crs.H, err = rand.GetG1()
	require.NoError(t, err)

	R, err := rand.GetG1()
	require.NoError(t, err)
	S, err := rand.GetG1()
	require.NoError(t, err)

	k, err := rand.GetFr()
	require.NoError(t, err)
	r_t, err := rand.GetFr()
	require.NoError(t, err)
	r_u, err := rand.GetFr()
	require.NoError(t, err)

	cm_T := groupcommitment.New(&crs.G_t, &crs.H, (&bls12381.G1Jac{}).ScalarMultiplication(&R, common.FrToBigInt(&k)), &r_t)
	cm_U := groupcommitment.New(&crs.G_u, &crs.H, (&bls12381.G1Jac{}).ScalarMultiplication(&S, common.FrToBigInt(&k)), &r_u)

	proof, err := Prove(
		&crs,
		&R,
		&S,
		cm_T,
		cm_U,
		&k,
		&r_t,
		&r_u,
		transcriptProver,
		rand,
	)

	// Reset the FS
	transcriptVerifier := transcript.New([]byte("same_scalar"))
	require.True(t, Verify(
		&proof,
		&crs,
		&R,
		&S,
		cm_T,
		cm_U,
		transcriptVerifier,
	))
}
