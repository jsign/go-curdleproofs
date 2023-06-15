package common

import (
	"math/big"
	"runtime"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

var MultiExpConf = ecc.MultiExpConfig{NbTasks: runtime.NumCPU()}

func FrToBigInt(r *fr.Element) *big.Int {
	var ret big.Int
	r.BigInt(&ret)
	return &ret
}

func SplitAt[T any](s []T, n uint) ([]T, []T) {
	return s[:n], s[n:]
}

func IPA(a []fr.Element, b []fr.Element) fr.Element {
	if len(a) != len(b) {
		panic("IPA: len(a) != len(b)")
	}
	var res fr.Element
	for i := range a {
		var term fr.Element
		term.Mul(&a[i], &b[i])
		res.Add(&res, &term)
	}
	return res
}

func Permute[T any](vs []T, perm []uint32) []T {
	ret := make([]T, len(vs))
	for i := range perm {
		ret[i] = vs[perm[i]]
	}
	return ret
}
