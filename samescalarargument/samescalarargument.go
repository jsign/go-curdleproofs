package samescalarargument

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/groupcommitment"
	"github.com/jsign/curdleproofs/transcript"
)

type Proof struct {
	Cm_A groupcommitment.GroupCommitment
	Cm_B groupcommitment.GroupCommitment
	Z_k  fr.Element
	Z_t  fr.Element
	Z_u  fr.Element
}

func Prove(
	crs *CRS,
	R, S *bls12381.G1Jac,
	cm_T, cm_U *groupcommitment.GroupCommitment,
	k, r_t, r_u *fr.Element,
	transcript *transcript.Transcript,
	rand *common.Rand,
) (Proof, error) {
	r_a, err := rand.GetFr()
	if err != nil {
		return Proof{}, fmt.Errorf("get r_a: %s", err)
	}
	r_b, err := rand.GetFr()
	if err != nil {
		return Proof{}, fmt.Errorf("get r_b: %s", err)
	}
	r_k, err := rand.GetFr()
	if err != nil {
		return Proof{}, fmt.Errorf("get r_k: %s", err)
	}
	var bi_r_k big.Int
	r_k.BigInt(&bi_r_k)

	cm_A := groupcommitment.New(&crs.G_t, &crs.H, (&bls12381.G1Jac{}).ScalarMultiplication(R, &bi_r_k), &r_a)
	cm_B := groupcommitment.New(&crs.G_u, &crs.H, (&bls12381.G1Jac{}).ScalarMultiplication(S, &bi_r_k), &r_b)

	transcript.AppendPoints([]byte("sameexp_points"), []bls12381.G1Jac{
		*R, *S,
		cm_T.T_1, cm_T.T_2,
		cm_U.T_1, cm_U.T_2,
		cm_A.T_1, cm_A.T_2,
		cm_B.T_1, cm_B.T_2,
	})

	alpha := transcript.GetChallenge([]byte("same_scalar_alpha"))

	z_k := (&fr.Element{}).Add(&r_k, (&fr.Element{}).Mul(k, &alpha))
	z_t := (&fr.Element{}).Add(&r_a, (&fr.Element{}).Mul(r_t, &alpha))
	z_u := (&fr.Element{}).Add(&r_b, (&fr.Element{}).Mul(r_u, &alpha))

	return Proof{
		Cm_A: *cm_A,
		Cm_B: *cm_B,
		Z_k:  *z_k,
		Z_t:  *z_t,
		Z_u:  *z_u,
	}, nil
}

func Verify(
	proof *Proof,
	crs *CRS,
	R, S *bls12381.G1Jac,
	cm_T, cm_U *groupcommitment.GroupCommitment,
	transcript *transcript.Transcript,
) bool {
	transcript.AppendPoints(
		[]byte("sameexp_points"),
		[]bls12381.G1Jac{
			*R, *S,
			cm_T.T_1, cm_T.T_2,
			cm_U.T_1, cm_U.T_2,
			proof.Cm_A.T_1, proof.Cm_A.T_2,
			proof.Cm_B.T_1, proof.Cm_B.T_2,
		},
	)
	alpha := transcript.GetChallenge([]byte("same_scalar_alpha"))

	expected_1 := groupcommitment.New(&crs.G_t, &crs.H, (&bls12381.G1Jac{}).ScalarMultiplication(R, common.FrToBigInt(&proof.Z_k)), &proof.Z_t)
	expected_2 := groupcommitment.New(&crs.G_u, &crs.H, (&bls12381.G1Jac{}).ScalarMultiplication(S, common.FrToBigInt(&proof.Z_k)), &proof.Z_u)

	if proof.Cm_A.Add(cm_T.Mul(alpha)).Eq(expected_1) &&
		proof.Cm_B.Add(cm_U.Mul(alpha)).Eq(expected_2) {
		return true
	}
	return false
}
