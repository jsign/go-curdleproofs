package samescalarargument

import (
	"fmt"
	"io"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/groupcommitment"
	"github.com/jsign/curdleproofs/transcript"
)

var (
	labelPoints = []byte("sameexp_points")
	labelAlpha  = []byte("sameexp_alpha")
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
	crs CRS,
	R bls12381.G1Jac,
	S bls12381.G1Jac,
	T groupcommitment.GroupCommitment,
	U groupcommitment.GroupCommitment,
	k fr.Element,
	r_t fr.Element,
	r_u fr.Element,
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
	A := groupcommitment.New(crs.Gt, crs.H, *tmp.ScalarMultiplication(&R, &bi_r_k), r_a)
	B := groupcommitment.New(crs.Gu, crs.H, *tmp.ScalarMultiplication(&S, &bi_r_k), r_b)

	transcript.AppendPoints(labelPoints, R, S, T.T_1, T.T_2, U.T_1, U.T_2, A.T_1, A.T_2, B.T_1, B.T_2)

	alpha := transcript.GetAndAppendChallenge(labelAlpha)

	var z_k, z_t, z_u fr.Element
	z_k.Add(&r_k, z_k.Mul(&k, &alpha))
	z_t.Add(&r_a, z_t.Mul(&r_t, &alpha))
	z_u.Add(&r_b, z_u.Mul(&r_u, &alpha))

	return Proof{
		A:   A,
		B:   B,
		Z_k: z_k,
		Z_t: z_t,
		Z_u: z_u,
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
	transcript.AppendPoints(labelPoints, R, S, T.T_1, T.T_2, U.T_1, U.T_2, proof.A.T_1, proof.A.T_2, proof.B.T_1, proof.B.T_2)
	alpha := transcript.GetAndAppendChallenge(labelAlpha)

	var tmp bls12381.G1Jac
	expected_1 := groupcommitment.New(crs.Gt, crs.H, *tmp.ScalarMultiplication(&R, common.FrToBigInt(&proof.Z_k)), proof.Z_t)
	expected_2 := groupcommitment.New(crs.Gu, crs.H, *tmp.ScalarMultiplication(&S, common.FrToBigInt(&proof.Z_k)), proof.Z_u)

	return proof.A.Add(T.Mul(alpha)).Eq(&expected_1) && proof.B.Add(U.Mul(alpha)).Eq(&expected_2)
}

func (p *Proof) FromReader(r io.Reader) error {
	if err := p.A.FromReader(r); err != nil {
		return fmt.Errorf("read A: %s", err)
	}
	if err := p.B.FromReader(r); err != nil {
		return fmt.Errorf("read B: %s", err)
	}
	d := bls12381.NewDecoder(r)
	if err := d.Decode(&p.Z_k); err != nil {
		return fmt.Errorf("read Z_k: %s", err)
	}
	if err := d.Decode(&p.Z_t); err != nil {
		return fmt.Errorf("read Z_t: %s", err)
	}
	if err := d.Decode(&p.Z_u); err != nil {
		return fmt.Errorf("read Z_u: %s", err)
	}
	return nil
}
