package common

import (
	"errors"
	"math/big"
	"runtime"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
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

func IPA(a []fr.Element, b []fr.Element) (fr.Element, error) {
	if len(a) != len(b) {
		return fr.Element{}, errors.New("IPA: len(a) != len(b)")
	}
	var res, tmp fr.Element
	for i := range a {
		res.Add(&res, tmp.Mul(&a[i], &b[i]))
	}
	return res, nil
}

func Permute[T any](vs []T, perm []uint32) []T {
	ret := make([]T, len(vs))
	for i := range perm {
		ret[i] = vs[perm[i]]
	}
	return ret
}

func DecodeAffineSliceToJac(d *bls12381.Decoder, out *[]bls12381.G1Jac) error {
	var affs []bls12381.G1Affine
	if err := d.Decode(&affs); err != nil {
		return err
	}
	*out = make([]bls12381.G1Jac, len(affs))
	for i := range affs {
		(*out)[i].FromAffine(&affs[i])
	}

	return nil
}
