package msmaccumulator

import (
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
)

type MsmAccumulator struct {
	A_c           bls12381.G1Jac
	baseScalarMap map[bls12381.G1Affine]fr.Element
}

func New() *MsmAccumulator {
	return &MsmAccumulator{
		A_c:           bls12381.G1Jac{},
		baseScalarMap: make(map[bls12381.G1Affine]fr.Element),
	}
}

func (ma *MsmAccumulator) AccumulateCheck(C bls12381.G1Jac, x []fr.Element, v []bls12381.G1Affine, rand *common.Rand) error {
	if len(v) != len(x) {
		return fmt.Errorf("x and v must have the same length")
	}

	alpha, err := rand.GetFr()
	if err != nil {
		return fmt.Errorf("get random scalar: %s", err)
	}
	for i := 0; i < len(v); i++ {
		var tmp fr.Element
		tmp.Mul(&alpha, &x[i])
		scalar := ma.baseScalarMap[v[i]]
		scalar.Add(&scalar, &tmp)
		ma.baseScalarMap[v[i]] = scalar
	}

	ma.A_c.AddAssign(C.ScalarMultiplication(&C, common.FrToBigInt(&alpha)))

	return nil
}

func (ma *MsmAccumulator) Verify() (bool, error) {
	x := make([]fr.Element, 0, len(ma.baseScalarMap))
	v := make([]bls12381.G1Affine, 0, len(ma.baseScalarMap))

	for vi := range ma.baseScalarMap {
		v = append(v, vi)
		x = append(x, ma.baseScalarMap[vi])
	}

	var msmRes bls12381.G1Jac
	if _, err := msmRes.MultiExp(v, x, common.MultiExpConf); err != nil {
		return false, fmt.Errorf("computing msm: %s", err)
	}

	return msmRes.Equal(&ma.A_c), nil
}
