package grandproductargument

import (
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/msmaccumulator"
	"github.com/jsign/curdleproofs/transcript"
	"github.com/stretchr/testify/require"
)

func TestGrandProductArgument(t *testing.T) {
	t.Parallel()

	n := 128
	numBlinders := 4

	rand, err := common.NewRand(0)
	require.NoError(t, err)

	var proof Proof
	{
		transcriptProver := transcript.New([]byte("gprod"))

		crsGs, err := rand.GetG1Affines(n - numBlinders)
		require.NoError(t, err)
		crsHs, err := rand.GetG1Affines(numBlinders)
		require.NoError(t, err)
		crsH, err := rand.GetG1Jac()
		require.NoError(t, err)
		crs := CRS{
			Gs: crsGs,
			Hs: crsHs,
			H:  crsH,
		}

		bs, err := rand.GetFrs(n - numBlinders)
		require.NoError(t, err)
		r_bs, err := rand.GetFrs(numBlinders)
		require.NoError(t, err)

		result := fr.One()
		for _, b := range bs {
			result.Mul(&result, &b)
		}

		var B, B_L, B_R bls12381.G1Jac
		_, err = B_L.MultiExp(crsGs, bs, common.MultiExpConf)
		require.NoError(t, err)
		_, err = B_R.MultiExp(crsHs, r_bs, common.MultiExpConf)
		require.NoError(t, err)
		B.AddAssign(&B_L).AddAssign(&B_R)

		proof, err = Prove(
			&crs,
			B,
			result,
			bs,
			r_bs,
			transcriptProver,
			rand,
		)
		require.NoError(t, err)
	}

	{
		rando, err := common.NewRand(0)
		require.NoError(t, err)

		transcriptVerifier := transcript.New([]byte("gprod"))
		msmAccumulator := msmaccumulator.New()

		crsGs, err := rando.GetG1Affines(n - numBlinders)
		require.NoError(t, err)
		crsHs, err := rando.GetG1Affines(numBlinders)
		require.NoError(t, err)
		crsH, err := rando.GetG1Jac()
		require.NoError(t, err)
		var Gsum bls12381.G1Affine
		for _, g := range crsGs {
			Gsum.Add(&Gsum, &g)
		}
		var Hsum bls12381.G1Affine
		for _, h := range crsHs {
			Hsum.Add(&Hsum, &h)
		}
		crs := CRS{
			Gs: crsGs,
			Hs: crsHs,
			H:  crsH,
		}
		bs, err := rando.GetFrs(n - numBlinders)
		require.NoError(t, err)
		r_bs, err := rando.GetFrs(numBlinders)
		require.NoError(t, err)

		result := fr.One()
		for _, b := range bs {
			result.Mul(&result, &b)
		}

		var B, B_L, B_R bls12381.G1Jac
		_, err = B_L.MultiExp(crsGs, bs, common.MultiExpConf)
		require.NoError(t, err)
		_, err = B_R.MultiExp(crsHs, r_bs, common.MultiExpConf)
		require.NoError(t, err)
		B.AddAssign(&B_L).AddAssign(&B_R)

		ok, err := Verify(
			proof,
			&crs,
			&Gsum,
			&Hsum,
			&B,
			result,
			numBlinders,
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
