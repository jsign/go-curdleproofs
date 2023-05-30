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
