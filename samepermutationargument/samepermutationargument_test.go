package samepermutationargument

import (
	"bytes"
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

	crs, A, M, as, perm, rs_a, rs_m := setup(t, n)
	transcriptProver := transcript.New([]byte("sameperm"))
	proof, err := Prove(
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

	t.Run("completeness", func(t *testing.T) {
		crs, A, M, as, _, _, _ := setup(t, n)
		transcriptVerifier := transcript.New([]byte("sameperm"))
		msmAccumulator := msmaccumulator.New()

		var Gsum bls12381.G1Affine
		for _, g := range crs.Gs {
			Gsum.Add(&Gsum, &g)
		}
		var Hsum bls12381.G1Affine
		for _, h := range crs.Hs {
			Hsum.Add(&Hsum, &h)
		}

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
	})

	t.Run("encode/decode", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)
		require.NoError(t, proof.Serialize(buf))
		expected := buf.Bytes()

		var proof2 Proof
		require.NoError(t, proof2.FromReader(buf))

		buf2 := bytes.NewBuffer(nil)
		require.NoError(t, proof2.Serialize(buf2))

		require.Equal(t, expected, buf2.Bytes())
	})
}

func setup(t *testing.T, n int) (CRS, bls12381.G1Jac, bls12381.G1Jac, []fr.Element, []uint32, []fr.Element, []fr.Element) {
	rand, err := common.NewRand(0)
	require.NoError(t, err)

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

	return crs, A, M, as, perm, rs_a, rs_m
}
