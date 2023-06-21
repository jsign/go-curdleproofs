package curdleproof

import (
	"testing"

	mrand "math/rand"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/jsign/curdleproofs/common"
	"github.com/stretchr/testify/require"
)

func TestCompleteness(t *testing.T) {
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
	ok, err := Verify(proof, crs, Rs, Ss, Ts, Us, M, rand)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestSoundness(t *testing.T) {
	t.Parallel()

	n := 128

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

	anotherPerm := make([]uint32, n-common.N_BLINDERS)
	for i := range anotherPerm {
		anotherPerm[i] = uint32(i)
	}
	srand.Shuffle(len(anotherPerm), func(i, j int) { anotherPerm[i], anotherPerm[j] = anotherPerm[j], anotherPerm[i] })

	t.Run("flips Ss and Rs", func(t *testing.T) {
		ok, err := Verify(proof, crs, Ss, Rs, Ts, Us, M, rand)
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("apply a different permutation than the one proved", func(t *testing.T) {
		ok, err := Verify(
			proof,
			crs,
			Rs,
			Ss,
			common.Permute(Ts, anotherPerm),
			common.Permute(Us, anotherPerm),
			M,
			rand,
		)
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("provide wrong perm commitment", func(t *testing.T) {
		biK := common.FrToBigInt(&k)
		var touchedM bls12381.G1Jac
		touchedM.ScalarMultiplication(&M, biK)
		ok, err := Verify(
			proof,
			crs,
			Rs,
			Ss,
			Ts,
			Us,
			touchedM,
			rand,
		)
		require.NoError(t, err)
		require.False(t, ok)

	})

	t.Run("instance outputs use a different randomizer", func(t *testing.T) {
		anotherK, err := rand.GetFr()
		require.NoError(t, err)
		biAnotherK := common.FrToBigInt(&anotherK)

		anotherTs := make([]bls12381.G1Affine, len(Rs))
		for i := range Ts {
			anotherTs[i].ScalarMultiplication(&Ts[i], biAnotherK)
		}

		anotherUs := make([]bls12381.G1Affine, len(Us))
		for i := range Us {
			anotherUs[i].ScalarMultiplication(&Us[i], biAnotherK)
		}
		ok, err := Verify(
			proof,
			crs,
			Rs,
			Ss,
			anotherTs,
			anotherUs,
			M,
			rand,
		)
		require.NoError(t, err)
		require.False(t, ok)

	})
}
