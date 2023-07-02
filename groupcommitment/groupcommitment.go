package groupcommitment

import (
	"fmt"
	"io"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
)

type GroupCommitment struct {
	T_1 bls12381.G1Jac
	T_2 bls12381.G1Jac
}

func New(
	crsG bls12381.G1Jac,
	crsH bls12381.G1Jac,
	T bls12381.G1Jac,
	r fr.Element,
) GroupCommitment {
	var T_1, T_2, tmp bls12381.G1Jac
	T_1.ScalarMultiplication(&crsG, common.FrToBigInt(&r))
	T_2.Set(&T).AddAssign(tmp.ScalarMultiplication(&crsH, common.FrToBigInt(&r)))

	return GroupCommitment{
		T_1: T_1,
		T_2: T_2,
	}
}

func (gc *GroupCommitment) Add(cm GroupCommitment) GroupCommitment {
	ret := GroupCommitment{}
	ret.T_1.Set(&gc.T_1).AddAssign(&cm.T_1)
	ret.T_2.Set(&gc.T_2).AddAssign(&cm.T_2)

	return ret
}

func (gc *GroupCommitment) Mul(scalar fr.Element) GroupCommitment {
	bigIntScalar := common.FrToBigInt(&scalar)
	ret := GroupCommitment{}
	ret.T_1.ScalarMultiplication(&gc.T_1, bigIntScalar)
	ret.T_2.ScalarMultiplication(&gc.T_2, bigIntScalar)

	return ret
}

func (t GroupCommitment) Eq(cm *GroupCommitment) bool {
	return t.T_1.Equal(&cm.T_1) && t.T_2.Equal(&cm.T_2)
}

func (gc *GroupCommitment) FromReader(r io.Reader) error {
	d := bls12381.NewDecoder(r)
	var tmp bls12381.G1Affine

	if err := d.Decode(&tmp); err != nil {
		return fmt.Errorf("decoding T_1: %s", err)
	}
	gc.T_1.FromAffine(&tmp)

	if err := d.Decode(&tmp); err != nil {
		return fmt.Errorf("decoding T_2: %s", err)
	}
	gc.T_2.FromAffine(&tmp)

	return nil
}

func (gc *GroupCommitment) Serialize(w io.Writer) error {
	ts := bls12381.BatchJacobianToAffineG1([]bls12381.G1Jac{gc.T_1, gc.T_2})
	e := bls12381.NewEncoder(w)
	if err := e.Encode(&ts[0]); err != nil {
		return fmt.Errorf("encoding T_1: %s", err)
	}
	if err := e.Encode(&ts[1]); err != nil {
		return fmt.Errorf("encoding T_2: %s", err)
	}
	return nil
}
