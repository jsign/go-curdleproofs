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

type CRS struct {
	Gt bls12381.G1Jac
	Gu bls12381.G1Jac
	H  bls12381.G1Jac
}

type Proof struct {
	A   groupcommitment.GroupCommitment
	B   groupcommitment.GroupCommitment
	Z_k fr.Element
	Z_t fr.Element
	Z_u fr.Element
}

func Prove(
	crs *CRS,
	R *bls12381.G1Jac,
	S *bls12381.G1Jac,
	T groupcommitment.GroupCommitment,
	U groupcommitment.GroupCommitment,
	k *fr.Element,
	r_t *fr.Element,
	r_u *fr.Element,
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

	var tmp bls12381.G1Jac
	A := groupcommitment.New(crs.Gt, crs.H, *tmp.ScalarMultiplication(R, &bi_r_k), r_a)
	B := groupcommitment.New(crs.Gu, crs.H, *tmp.ScalarMultiplication(S, &bi_r_k), r_b)

	transcript.AppendPoints([]byte("sameexp_points"),
		R, S,
		&T.T_1, &T.T_2,
		&U.T_1, &U.T_2,
		&A.T_1, &A.T_2,
		&B.T_1, &B.T_2,
	)

	alpha := transcript.GetAndAppendChallenge([]byte("same_scalar_alpha"))

	z_k := (&fr.Element{}).Add(&r_k, (&fr.Element{}).Mul(k, &alpha))
	z_t := (&fr.Element{}).Add(&r_a, (&fr.Element{}).Mul(r_t, &alpha))
	z_u := (&fr.Element{}).Add(&r_b, (&fr.Element{}).Mul(r_u, &alpha))

	return Proof{
		A:   A,
		B:   B,
		Z_k: *z_k,
		Z_t: *z_t,
		Z_u: *z_u,
	}, nil
}

func Verify(
	proof Proof,
	crs CRS,
	R bls12381.G1Jac,
	S bls12381.G1Jac,
	T groupcommitment.GroupCommitment,
	U groupcommitment.GroupCommitment,
	transcript *transcript.Transcript,
) bool {
	transcript.AppendPoints(
		[]byte("sameexp_points"),
		&R, &S,
		&T.T_1, &T.T_2,
		&U.T_1, &U.T_2,
		&proof.A.T_1, &proof.A.T_2,
		&proof.B.T_1, &proof.B.T_2,
	)
	alpha := transcript.GetAndAppendChallenge([]byte("same_scalar_alpha"))

	var tmp bls12381.G1Jac
	expected_1 := groupcommitment.New(crs.Gt, crs.H, *tmp.ScalarMultiplication(&R, common.FrToBigInt(&proof.Z_k)), proof.Z_t)
	expected_2 := groupcommitment.New(crs.Gu, crs.H, *tmp.ScalarMultiplication(&S, common.FrToBigInt(&proof.Z_k)), proof.Z_u)

	return proof.A.Add(T.Mul(alpha)).Eq(&expected_1) && proof.B.Add(U.Mul(alpha)).Eq(&expected_2)
}
