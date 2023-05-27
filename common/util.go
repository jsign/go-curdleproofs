package common

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func FrToBigInt(r *fr.Element) *big.Int {
	var ret big.Int
	r.BigInt(&ret)
	return &ret
}
