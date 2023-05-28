package common

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func FrToBigInt(r *fr.Element) *big.Int {
	var ret big.Int
	r.BigInt(&ret)
	return &ret
}

func GenerateBlindersFr(rand Rand, n uint) ([]fr.Element, error) {
	var err error
	ret := make([]fr.Element, n)
	for i := uint(0); i < n; i++ {
		ret[i], err = rand.GetFr()
		if err != nil {
			return nil, fmt.Errorf("generating Fr: %s", err)
		}
	}
	return ret, nil
}

func SplitAt[T any](s []T, n uint) ([]T, []T) {
	return s[:n], s[n:]
}
