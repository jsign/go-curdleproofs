package samemultiscalarargument

import (
	"fmt"
	"io"
	"math/bits"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/msmaccumulator"
	"github.com/jsign/curdleproofs/transcript"
)

var (
	labelStep1 = []byte("same_msm_step1")
	labelAlpha = []byte("same_msm_alpha")
	labelLoop  = []byte("same_msm_loop")
	labelGamma = []byte("same_msm_gamma")
)

type Proof struct {
	B_a bls12381.G1Jac
	B_t bls12381.G1Jac
	B_u bls12381.G1Jac

	L_A []bls12381.G1Jac
	L_T []bls12381.G1Jac
	L_U []bls12381.G1Jac
	R_A []bls12381.G1Jac
	R_T []bls12381.G1Jac
	R_U []bls12381.G1Jac

	x fr.Element
}

func Prove(
	G []bls12381.G1Affine,
	A bls12381.G1Jac,
	Z_t bls12381.G1Jac,
	Z_u bls12381.G1Jac,
	T []bls12381.G1Affine,
	U []bls12381.G1Affine,
	x []fr.Element,
	transcript *transcript.Transcript,
	rand *common.Rand,
) (Proof, error) {
	n := uint(len(x))
	m := bits.Len(n) - 1

	L_Ts := make([]bls12381.G1Jac, 0, m)
	R_Ts := make([]bls12381.G1Jac, 0, m)
	L_Us := make([]bls12381.G1Jac, 0, m)
	R_Us := make([]bls12381.G1Jac, 0, m)
	L_As := make([]bls12381.G1Jac, 0, m)
	R_As := make([]bls12381.G1Jac, 0, m)

	r, err := rand.GetFrs(int(n))
	if err != nil {
		return Proof{}, fmt.Errorf("generating blinders: %s", err)
	}

	var B_a, B_t, B_u bls12381.G1Jac
	if _, err := B_a.MultiExp(G, r, common.MultiExpConf); err != nil {
		return Proof{}, fmt.Errorf("computing B_a: %s", err)
	}
	if _, err := B_t.MultiExp(T, r, common.MultiExpConf); err != nil {
		return Proof{}, fmt.Errorf("computing B_t: %s", err)
	}
	if _, err := B_u.MultiExp(U, r, common.MultiExpConf); err != nil {
		return Proof{}, fmt.Errorf("computing B_u: %s", err)
	}

	transcript.AppendPoints(labelStep1, A, Z_t, Z_u)
	transcript.AppendPointsAffine(labelStep1, T...)
	transcript.AppendPointsAffine(labelStep1, U...)
	transcript.AppendPoints(labelStep1, B_a, B_t, B_u)
	alpha := transcript.GetAndAppendChallenge(labelAlpha)

	var tmp fr.Element
	for i := range x {
		x[i].Add(&r[i], tmp.Mul(&x[i], &alpha))
	}

	for len(x) > 1 {
		n /= 2

		x_L, x_R := common.SplitAt(x, n)
		T_L, T_R := common.SplitAt(T, n)
		U_L, U_R := common.SplitAt(U, n)
		G_L, G_R := common.SplitAt(G, n)

		var L_A, L_T, L_U, R_A, R_T, R_U bls12381.G1Jac
		if _, err := L_A.MultiExp(G_R, x_L, common.MultiExpConf); err != nil {
			return Proof{}, fmt.Errorf("computing L_A: %s", err)
		}
		if _, err := L_T.MultiExp(T_R, x_L, common.MultiExpConf); err != nil {
			return Proof{}, fmt.Errorf("computing L_T: %s", err)
		}
		if _, err := L_U.MultiExp(U_R, x_L, common.MultiExpConf); err != nil {
			return Proof{}, fmt.Errorf("computing L_U: %s", err)
		}
		if _, err := R_A.MultiExp(G_L, x_R, common.MultiExpConf); err != nil {
			return Proof{}, fmt.Errorf("computing R_A: %s", err)
		}
		if _, err := R_T.MultiExp(T_L, x_R, common.MultiExpConf); err != nil {
			return Proof{}, fmt.Errorf("computing R_T: %s", err)
		}
		if _, err := R_U.MultiExp(U_L, x_R, common.MultiExpConf); err != nil {
			return Proof{}, fmt.Errorf("computing R_U: %s", err)
		}

		L_As = append(L_As, L_A)
		L_Ts = append(L_Ts, L_T)
		L_Us = append(L_Us, L_U)
		R_As = append(R_As, R_A)
		R_Ts = append(R_Ts, R_T)
		R_Us = append(R_Us, R_U)

		transcript.AppendPoints(labelLoop, L_A, L_T, L_U, R_A, R_T, R_U)
		gamma := transcript.GetAndAppendChallenge(labelGamma)
		if gamma.IsZero() {
			return Proof{}, fmt.Errorf("gamma is zero")
		}
		var gamma_inv fr.Element
		gamma_inv.Inverse(&gamma)

		// Fold vectors and basis
		for i := 0; i < int(n); i++ {
			gammaBigInt := common.FrToBigInt(&gamma)
			x_L[i].Add(&x_L[i], (&fr.Element{}).Mul(&gamma_inv, &x_R[i]))
			T_L[i].Add(&T_L[i], (&bls12381.G1Affine{}).ScalarMultiplication(&T_R[i], gammaBigInt))
			U_L[i].Add(&U_L[i], (&bls12381.G1Affine{}).ScalarMultiplication(&U_R[i], gammaBigInt))
			G_L[i].Add(&G_L[i], (&bls12381.G1Affine{}).ScalarMultiplication(&G_R[i], gammaBigInt))
		}
		x = x_L
		T = T_L
		U = U_L
		G = G_L
	}
	if len(x) != 1 {
		return Proof{}, fmt.Errorf("unexpected length of x")
	}

	return Proof{
		B_a: B_a,
		B_t: B_t,
		B_u: B_u,
		L_A: L_As,
		L_T: L_Ts,
		L_U: L_Us,
		R_A: R_As,
		R_T: R_Ts,
		R_U: R_Us,
		x:   x[0],
	}, nil
}

func Verify(
	proof Proof,
	G []bls12381.G1Affine,
	A bls12381.G1Jac,
	Z_t bls12381.G1Jac,
	Z_u bls12381.G1Jac,
	T []bls12381.G1Affine,
	U []bls12381.G1Affine,
	transcript *transcript.Transcript,
	msmacc *msmaccumulator.MsmAccumulator,
	rand *common.Rand,
) (bool, error) {
	n := len(T)

	transcript.AppendPoints(labelStep1, A, Z_t, Z_u)
	transcript.AppendPointsAffine(labelStep1, T...)
	transcript.AppendPointsAffine(labelStep1, U...)
	transcript.AppendPoints(labelStep1, proof.B_a, proof.B_t, proof.B_u)
	alpha := transcript.GetAndAppendChallenge(labelAlpha)

	gamma, gamma_inv, s, err := unfoldedScalars(&proof, n, transcript)
	if err != nil {
		return false, fmt.Errorf("computing verification scalars: %s", err)
	}

	xtimess := make([]fr.Element, len(s))
	for i := 0; i < len(s); i++ {
		xtimess[i].Mul(&proof.x, &s[i])
	}

	var A_a, Z_t_a, Z_u_a bls12381.G1Jac
	A_a.Set(&proof.B_a).AddAssign((&bls12381.G1Jac{}).ScalarMultiplication(&A, common.FrToBigInt(&alpha)))
	Z_t_a.Set(&proof.B_t).AddAssign((&bls12381.G1Jac{}).ScalarMultiplication(&Z_t, common.FrToBigInt(&alpha)))
	Z_u_a.Set(&proof.B_u).AddAssign((&bls12381.G1Jac{}).ScalarMultiplication(&Z_u, common.FrToBigInt(&alpha)))

	var l, p, r bls12381.G1Jac
	L_A_Affine := bls12381.BatchJacobianToAffineG1(proof.L_A)
	if _, err := l.MultiExp(L_A_Affine, gamma, common.MultiExpConf); err != nil {
		return false, fmt.Errorf("computing point_lhs msm: %s", err)
	}
	R_A_Affine := bls12381.BatchJacobianToAffineG1(proof.R_A)
	if _, err := r.MultiExp(R_A_Affine, gamma_inv, common.MultiExpConf); err != nil {
		return false, fmt.Errorf("computing point_lhs msm: %s", err)
	}
	p.Set(&A_a).AddAssign(&l).AddAssign(&r)
	var p_affine bls12381.G1Affine
	p_affine.FromJacobian(&p)
	if err := msmacc.AccumulateCheck(p, xtimess, G, rand); err != nil {
		return false, fmt.Errorf("accumulating msm 1: %s", err)
	}
	L_T_Affine := bls12381.BatchJacobianToAffineG1(proof.L_T)
	if _, err := l.MultiExp(L_T_Affine, gamma, common.MultiExpConf); err != nil {
		return false, fmt.Errorf("computing point_lhs msm: %s", err)
	}
	R_T_Affine := bls12381.BatchJacobianToAffineG1(proof.R_T)
	if _, err := r.MultiExp(R_T_Affine, gamma_inv, common.MultiExpConf); err != nil {
		return false, fmt.Errorf("computing point_lhs msm: %s", err)
	}
	p.Set(&Z_t_a).AddAssign(&l).AddAssign(&r)
	if err := msmacc.AccumulateCheck(p, xtimess, T, rand); err != nil {
		return false, fmt.Errorf("accumulating msm 1: %s", err)
	}

	L_U_Affine := bls12381.BatchJacobianToAffineG1(proof.L_U)
	if _, err := l.MultiExp(L_U_Affine, gamma, common.MultiExpConf); err != nil {
		return false, fmt.Errorf("computing point_lhs msm: %s", err)
	}
	R_U_Affine := bls12381.BatchJacobianToAffineG1(proof.R_U)
	if _, err := r.MultiExp(R_U_Affine, gamma_inv, common.MultiExpConf); err != nil {
		return false, fmt.Errorf("computing point_lhs msm: %s", err)
	}
	p.Set(&Z_u_a).AddAssign(&l).AddAssign(&r)
	if err := msmacc.AccumulateCheck(p, xtimess, U, rand); err != nil {
		return false, fmt.Errorf("accumulating msm 1: %s", err)
	}
	return true, nil
}

const maxRecursiveSteps = 32

func unfoldedScalars(
	proof *Proof,
	n int,
	transcript *transcript.Transcript,
) ([]fr.Element, []fr.Element, []fr.Element, error) {
	lg_n := len(proof.L_A)
	if lg_n >= maxRecursiveSteps {
		return nil, nil, nil, fmt.Errorf("recursive steps greater than expected")
	}

	if n != (1 << lg_n) {
		return nil, nil, nil, fmt.Errorf("must by log2(L_a)")
	}

	challenges := make([]fr.Element, 0, lg_n)
	for i := range proof.L_A {
		transcript.AppendPoints(
			labelLoop,
			proof.L_A[i],
			proof.L_T[i],
			proof.L_U[i],
			proof.R_A[i],
			proof.R_T[i],
			proof.R_U[i],
		)
		challenges = append(challenges, transcript.GetAndAppendChallenge(labelGamma))
	}

	ss := make([]fr.Element, 0, n)
	for i := 0; i < n; i++ {
		tmp := fr.One()
		for k := lg_n - 1; k >= 0; k-- {
			bit := i&(1<<(lg_n-k-1)) > 0
			if bit {
				tmp.Mul(&tmp, &challenges[k])
			}
		}
		ss = append(ss, tmp)
	}

	return challenges, fr.BatchInvert(challenges), ss, nil
}

func (p *Proof) FromReader(r io.Reader) error {
	d := bls12381.NewDecoder(r)
	if err := d.Decode(&p.B_a); err != nil {
		return fmt.Errorf("decoding B_a: %s", err)
	}
	if err := d.Decode(&p.B_t); err != nil {
		return fmt.Errorf("decoding B_t: %s", err)
	}
	if err := d.Decode(&p.B_u); err != nil {
		return fmt.Errorf("decoding B_u: %s", err)
	}
	if err := d.Decode(&p.L_A); err != nil {
		return fmt.Errorf("decoding L_A: %s", err)
	}
	if err := d.Decode(&p.L_T); err != nil {
		return fmt.Errorf("decoding L_T: %s", err)
	}
	if err := d.Decode(&p.L_U); err != nil {
		return fmt.Errorf("decoding L_U: %s", err)
	}
	if err := d.Decode(&p.R_A); err != nil {
		return fmt.Errorf("decoding R_A: %s", err)
	}
	if err := d.Decode(&p.R_T); err != nil {
		return fmt.Errorf("decoding R_T: %s", err)
	}
	if err := d.Decode(&p.R_U); err != nil {
		return fmt.Errorf("decoding R_U: %s", err)
	}
	if err := d.Decode(&p.x); err != nil {
		return fmt.Errorf("decoding x: %s", err)
	}
	return nil
}
