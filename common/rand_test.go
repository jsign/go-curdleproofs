package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPermutation(t *testing.T) {
	t.Parallel()

	rand, err := NewRand(42)
	require.NoError(t, err)

	n := 10
	perm, err := rand.GeneratePermutation(n)
	require.NoError(t, err)

	for i := 0; i < 100; i++ {
		newPerm, err := rand.GeneratePermutation(n)
		require.NoError(t, err)
		require.NotEqual(t, perm, newPerm)
		perm = newPerm
	}
}
