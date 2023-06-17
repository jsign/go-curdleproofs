package innerproductargument

import (
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/msmaccumulator"
	"github.com/jsign/curdleproofs/transcript"
	"github.com/stretchr/testify/require"
)

func TestInnerProductArgument(t *testing.T) {
	t.Parallel()

	n := 128
	var proof Proof
	{
		transcript := transcript.New([]byte("IPA"))
		crs, B, C, z, bs, cs, _ := setup(t, n)

		rand, err := common.NewRand(42)
		require.NoError(t, err)
		proof, err = Prove(
			crs,
			B,
			C,
			z,
			bs,
			cs,
			transcript,
			rand,
		)
		require.NoError(t, err)
	}

	t.Run("Completeness", func(t *testing.T) {
		transcript := transcript.New([]byte("IPA"))
		msmAccumulator := msmaccumulator.New()
		crs, B, C, z, _, _, us := setup(t, n)

		rand, err := common.NewRand(43)
		require.NoError(t, err)

		ok, err := Verify(
			&proof,
			&crs,
			B,
			C,
			z,
			us,
			transcript,
			msmAccumulator,
			rand,
		)
		require.NoError(t, err)
		require.True(t, ok)

		ok, err = msmAccumulator.Verify()
		require.NoError(t, err)
		require.True(t, ok)
	})
}

func setup(t *testing.T, n int) (CRS, bls12381.G1Jac, bls12381.G1Jac, fr.Element, []fr.Element, []fr.Element, []fr.Element) {
	rand, err := common.NewRand(0)
	require.NoError(t, err)

	crsGs, err := rand.GetG1Affines(n)
	require.NoError(t, err)
	// There is actually a relationship between crs_G_vec and crs_G_prime_vec because of the grandproduct optimization
	// We generate a `vec_u` which has the discrete logs of every crs_G_prime element with respect to crs_G
	us, err := rand.GetFrs(n)
	require.NoError(t, err)
	crsGs_prime := make([]bls12381.G1Affine, n)
	for i := 0; i < n; i++ {
		crsGs_prime[i].ScalarMultiplication(&crsGs[i], common.FrToBigInt(&us[i]))
	}
	H, err := rand.GetG1Jac()
	require.NoError(t, err)
	crs := CRS{
		Gs:       crsGs,
		Gs_prime: crsGs_prime,
		H:        H,
	}

	// Generate some random vectors
	bs, err := rand.GetFrs(n)
	require.NoError(t, err)
	cs, err := rand.GetFrs(n)
	require.NoError(t, err)

	z, err := common.IPA(bs, cs)
	require.NoError(t, err)

	// Create commitments
	var B bls12381.G1Jac
	_, err = B.MultiExp(crs.Gs, bs, common.MultiExpConf)
	require.NoError(t, err)
	var C bls12381.G1Jac
	_, err = C.MultiExp(crs.Gs_prime, cs, common.MultiExpConf)
	require.NoError(t, err)

	return crs, B, C, z, bs, cs, us
}
