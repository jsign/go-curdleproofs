package common

import (
	"fmt"
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

func ShufflePermuteCommit(
	crsGs []bls12381.G1Affine,
	crsHs []bls12381.G1Affine,
	Rs []bls12381.G1Affine,
	Ss []bls12381.G1Affine,
	perm []uint32,
	k fr.Element,
	rand *Rand,
) ([]bls12381.G1Affine, []bls12381.G1Affine, bls12381.G1Jac, []fr.Element, error) {

	biK := FrToBigInt(&k)
	Ts := make([]bls12381.G1Affine, len(Rs))
	for i := range Ts {
		Ts[i].ScalarMultiplication(&Rs[i], biK)
	}

	Us := make([]bls12381.G1Affine, len(Ss))
	for i := range Us {
		Us[i].ScalarMultiplication(&Ss[i], biK)
	}

	T := Permute(Ts, perm)
	U := Permute(Us, perm)

	rangeFrs := make([]fr.Element, len(crsGs))
	for i := range perm {
		rangeFrs[i] = fr.NewElement(uint64(perm[i]))
	}
	permRangeFrs := Permute(rangeFrs, perm)

	var M1, M2 bls12381.G1Jac
	if _, err := M1.MultiExp(crsGs, permRangeFrs, MultiExpConf); err != nil {
		return nil, nil, bls12381.G1Jac{}, nil, fmt.Errorf("calculating M_1: %s", err)
	}
	rs_m, err := rand.GetFrs(N_BLINDERS)
	if err != nil {
		return nil, nil, bls12381.G1Jac{}, nil, fmt.Errorf("getting rs_m: %s", err)
	}
	if _, err := M2.MultiExp(crsHs, rs_m, MultiExpConf); err != nil {
		return nil, nil, bls12381.G1Jac{}, nil, fmt.Errorf("calculating M_2: %s", err)
	}
	M1.AddAssign(&M2)

	return T, U, M1, rs_m, nil
}
