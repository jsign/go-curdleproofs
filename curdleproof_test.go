package curdleproof

import (
	"testing"

	mrand "math/rand"

	"github.com/jsign/curdleproofs/common"
	"github.com/stretchr/testify/require"
)

func TestCurdleproof(t *testing.T) {
	t.Parallel()

	n := 64

	rand, err := common.NewRand(0)
	require.NoError(t, err)

	crs, err := GenerateCRS(n-common.N_BLINDERS, rand)
	require.NoError(t, err)

	perm := make([]uint32, n-common.N_BLINDERS)
	for i := range perm {
		perm[i] = uint32(i)
	}
	srand := mrand.New(mrand.NewSource(42))
	srand.Shuffle(len(perm), func(i, j int) { perm[i], perm[j] = perm[j], perm[i] })

	k, err := rand.GetFr()
	require.NoError(t, err)

	Rs, err := rand.GetG1Affines(n - common.N_BLINDERS)
	require.NoError(t, err)
	Ss, err := rand.GetG1Affines(n - common.N_BLINDERS)
	require.NoError(t, err)

	Ts, Us, M, rs_m, err := common.ShufflePermuteCommit(crs.Gs, crs.Hs, Rs, Ss, perm, k, rand)
	require.NoError(t, err)

	// Prove.
	rand, err = common.NewRand(0)
	require.NoError(t, err)
	proof, err := Prove(
		crs,
		Rs,
		Ss,
		Ts,
		Us,
		M,
		perm,
		k,
		rs_m,
		rand,
	)
	require.NoError(t, err)

	// Verify.
	rand, err = common.NewRand(0)
	require.NoError(t, err)
	ok, err := Verify(proof, crs, Rs, Ss, Ts, Us, M, rand)
	require.NoError(t, err)
	require.True(t, ok)
}

// TODO(jsign): Add soundness tests.
