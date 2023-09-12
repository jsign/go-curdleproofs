package samescalarargument

import (
	"fmt"
	"io"
	"math/big"

	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/group"
	"github.com/jsign/curdleproofs/transcript"
)

var (
	labelPoints = []byte("sameexp_points")
	labelAlpha  = []byte("sameexp_alpha")
)

type CRS struct {
	Gt group.Element
	Gu group.Element
	H  group.Element
}

type Proof struct {
	A   group.GroupCommitment
	B   group.GroupCommitment
	Z_k big.Int
	Z_t big.Int
	Z_u big.Int
}

func Prove(
	g group.Group,

	crs CRS,
	R group.Element,
	S group.Element,
	T group.GroupCommitment,
	U group.GroupCommitment,
	k big.Int,
	r_t big.Int,
	r_u big.Int,
	transcript *transcript.Transcript,
	rand *common.Rand,
) (Proof, error) {
	// TODO: 128 bytes random big.Int is arbitrary. It should be better defined,
	// regarding the underlying group order. Should be fine for an experiment.
	r_a, err := rand.GetBigInt128()
	if err != nil {
		return Proof{}, fmt.Errorf("get r_a: %s", err)
	}
	r_b, err := rand.GetBigInt128()
	if err != nil {
		return Proof{}, fmt.Errorf("get r_b: %s", err)
	}
	r_k, err := rand.GetBigInt128()
	if err != nil {
		return Proof{}, fmt.Errorf("get r_k: %s", err)
	}
	var bi_r_k = r_k // TODO: unnecessary, just to keep the the same names as the original code.

	tmp := g.CreateElement()
	A := group.NewGroupCommitment(g, crs.Gt, crs.H, tmp.ScalarMultiplication(R, &bi_r_k), &r_a)
	B := group.NewGroupCommitment(g, crs.Gu, crs.H, tmp.ScalarMultiplication(S, &bi_r_k), &r_b)

	transcript.AppendGroupElements(labelPoints, R, S, T.T_1, T.T_2, U.T_1, U.T_2, A.T_1, A.T_2, B.T_1, B.T_2)

	alpha := transcript.GetAndAppendChallengeBigInt(labelAlpha)

	var z_k, z_t, z_u big.Int
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
	g group.Group,

	proof Proof,
	crs CRS,
	R group.Element,
	S group.Element,
	T group.GroupCommitment,
	U group.GroupCommitment,
	transcript *transcript.Transcript,
) bool {
	transcript.AppendGroupElements(labelPoints, R, S, T.T_1, T.T_2, U.T_1, U.T_2, proof.A.T_1, proof.A.T_2, proof.B.T_1, proof.B.T_2)
	alpha := transcript.GetAndAppendChallengeBigInt(labelAlpha)

	tmp := g.CreateElement()
	expected_1 := group.NewGroupCommitment(g, crs.Gt, crs.H, tmp.ScalarMultiplication(R, &proof.Z_k), &proof.Z_t)
	expected_2 := group.NewGroupCommitment(g, crs.Gu, crs.H, tmp.ScalarMultiplication(S, &proof.Z_k), &proof.Z_u)

	return proof.A.Add(T.Mul(&alpha)).Eq(expected_1) && proof.B.Add(U.Mul(&alpha)).Eq(expected_2)
}

func (p *Proof) FromReader(r io.Reader) error {
	// if err := p.A.FromReader(r); err != nil {
	// 	return fmt.Errorf("read A: %s", err)
	// }
	// if err := p.B.FromReader(r); err != nil {
	// 	return fmt.Errorf("read B: %s", err)
	// }
	// d := bls12381.NewDecoder(r)
	// if err := d.Decode(&p.Z_k); err != nil {
	// 	return fmt.Errorf("read Z_k: %s", err)
	// }
	// if err := d.Decode(&p.Z_t); err != nil {
	// 	return fmt.Errorf("read Z_t: %s", err)
	// }
	// if err := d.Decode(&p.Z_u); err != nil {
	// 	return fmt.Errorf("read Z_u: %s", err)
	// }
	return nil
}

func (p *Proof) Serialize(w io.Writer) error {
	// if err := p.A.Serialize(w); err != nil {
	// 	return fmt.Errorf("write A: %s", err)
	// }
	// if err := p.B.Serialize(w); err != nil {
	// 	return fmt.Errorf("write B: %s", err)
	// }
	// e := bls12381.NewEncoder(w)
	// if err := e.Encode(&p.Z_k); err != nil {
	// 	return fmt.Errorf("write Z_k: %s", err)
	// }
	// if err := e.Encode(&p.Z_t); err != nil {
	// 	return fmt.Errorf("write Z_t: %s", err)
	// }
	// if err := e.Encode(&p.Z_u); err != nil {
	// 	return fmt.Errorf("write Z_u: %s", err)
	// }
	return nil
}
