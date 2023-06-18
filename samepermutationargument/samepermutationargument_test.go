package samepermutationargument

import (
	"testing"

	mrand "math/rand"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/msmaccumulator"
	"github.com/jsign/curdleproofs/transcript"
	"github.com/stretchr/testify/require"
)

func TestSamePermutationArgument(t *testing.T) {
	t.Parallel()

	n := 128

	rand, err := common.NewRand(0)
	require.NoError(t, err)

	var proof Proof
	{
		transcriptProver := transcript.New([]byte("sameperm"))

		crsGs, err := rand.GetG1Affines(n - common.N_BLINDERS)
		require.NoError(t, err)
		crsHs, err := rand.GetG1Affines(common.N_BLINDERS)
		require.NoError(t, err)
		crsH, err := rand.GetG1Jac()
		require.NoError(t, err)
		crs := CRS{
			Gs: crsGs,
			Hs: crsHs,
			H:  crsH,
		}

		rs_a, err := rand.GetFrs(common.N_BLINDERS)
		require.NoError(t, err)
		rs_m, err := rand.GetFrs(common.N_BLINDERS)
		require.NoError(t, err)

		perm := make([]uint32, n-common.N_BLINDERS)
		for i := range perm {
			perm[i] = uint32(i)
		}
		srand := mrand.New(mrand.NewSource(42))
		srand.Shuffle(len(perm), func(i, j int) { perm[i], perm[j] = perm[j], perm[i] })
		permFrs := make([]fr.Element, n-common.N_BLINDERS)
		for i := range perm {
			permFrs[i] = fr.NewElement(uint64(perm[i]))
		}

		as, err := rand.GetFrs(n - common.N_BLINDERS)
		require.NoError(t, err)
		permAs := common.Permute(as, perm)

		var A, A_L, A_R bls12381.G1Jac
		_, err = A_L.MultiExp(crsGs, permAs, common.MultiExpConf)
		require.NoError(t, err)
		_, err = A_R.MultiExp(crsHs, rs_a, common.MultiExpConf)
		require.NoError(t, err)
		A.Set(&A_L).AddAssign(&A_R)

		var M, M_L, M_R bls12381.G1Jac
		_, err = M_L.MultiExp(crsGs, permFrs, common.MultiExpConf)
		require.NoError(t, err)
		_, err = M_R.MultiExp(crsHs, rs_m, common.MultiExpConf)
		require.NoError(t, err)
		M.Set(&M_L).AddAssign(&M_R)

		proof, err = Prove(
			crs,
			A,
			M,
			as,
			perm,
			rs_a,
			rs_m,
			transcriptProver,
			rand,
		)
		require.NoError(t, err)
	}

	{
		rando, err := common.NewRand(0)
		require.NoError(t, err)

		crsGs, err := rando.GetG1Affines(n - common.N_BLINDERS)
		require.NoError(t, err)
		crsHs, err := rando.GetG1Affines(common.N_BLINDERS)
		require.NoError(t, err)
		crsH, err := rando.GetG1Jac()
		require.NoError(t, err)
		crs := CRS{
			Gs: crsGs,
			Hs: crsHs,
			H:  crsH,
		}
		var Gsum bls12381.G1Affine
		for _, g := range crsGs {
			Gsum.Add(&Gsum, &g)
		}
		var Hsum bls12381.G1Affine
		for _, h := range crsHs {
			Hsum.Add(&Hsum, &h)
		}
		transcriptVerifier := transcript.New([]byte("sameperm"))
		msmAccumulator := msmaccumulator.New()

		rs_a, err := rando.GetFrs(common.N_BLINDERS)
		require.NoError(t, err)
		rs_m, err := rando.GetFrs(common.N_BLINDERS)
		require.NoError(t, err)

		perm := make([]uint32, n-common.N_BLINDERS)
		for i := range perm {
			perm[i] = uint32(i)
		}
		srand := mrand.New(mrand.NewSource(42))
		srand.Shuffle(len(perm), func(i, j int) { perm[i], perm[j] = perm[j], perm[i] })
		permFrs := make([]fr.Element, n-common.N_BLINDERS)
		for i := range perm {
			permFrs[i] = fr.NewElement(uint64(perm[i]))
		}
		as, err := rando.GetFrs(n - common.N_BLINDERS)
		require.NoError(t, err)
		permAs := common.Permute(as, perm)

		var A, A_L, A_R bls12381.G1Jac
		_, err = A_L.MultiExp(crsGs, permAs, common.MultiExpConf)
		require.NoError(t, err)
		_, err = A_R.MultiExp(crsHs, rs_a, common.MultiExpConf)
		require.NoError(t, err)
		A.Set(&A_L).AddAssign(&A_R)

		var M, M_L, M_R bls12381.G1Jac
		_, err = M_L.MultiExp(crsGs, permFrs, common.MultiExpConf)
		require.NoError(t, err)
		_, err = M_R.MultiExp(crsHs, rs_m, common.MultiExpConf)
		require.NoError(t, err)
		M.Set(&M_L).AddAssign(&M_R)

		ok, err := Verify(
			proof,
			crs,
			Gsum,
			Hsum,
			A,
			M,
			as,
			common.N_BLINDERS,
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

// TODO(jsign): include soundness tests (and in other args)
