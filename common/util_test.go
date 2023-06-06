package common

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/require"
)

func TestIPA(t *testing.T) {
	a := []fr.Element{
		fr.NewElement(1),
		fr.NewElement(2),
		fr.NewElement(3),
		fr.NewElement(4),
	}
	b := []fr.Element{
		fr.NewElement(2),
		fr.NewElement(3),
		fr.NewElement(4),
		fr.NewElement(5),
	}
	got := IPA(a, b)
	exp := fr.NewElement(40)
	require.True(t, exp.Equal(&got))
}
