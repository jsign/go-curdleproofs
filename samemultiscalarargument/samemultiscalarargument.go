package samemultiscalarargument

import (
	"fmt"
	"math/bits"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/msmaccumulator"
	"github.com/jsign/curdleproofs/transcript"
)

type Proof struct {
	B_a *bls12381.G1Jac
	B_t *bls12381.G1Jac
	B_u *bls12381.G1Jac

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
	A *bls12381.G1Jac,
	Z_t *bls12381.G1Jac,
	Z_u *bls12381.G1Jac,
	T []bls12381.G1Affine,
	U []bls12381.G1Affine,

	x []fr.Element,

	transcript *transcript.Transcript,
	rand *common.Rand,
) (Proof, error) {
	n := uint(len(x))
	m := bits.Len(n) - 1

	vec_L_T := make([]bls12381.G1Jac, 0, m)
	vec_R_T := make([]bls12381.G1Jac, 0, m)
	vec_L_U := make([]bls12381.G1Jac, 0, m)
	vec_R_U := make([]bls12381.G1Jac, 0, m)
	vec_L_A := make([]bls12381.G1Jac, 0, m)
	vec_R_A := make([]bls12381.G1Jac, 0, m)

	r, err := rand.GetFrs(int(n))
	if err != nil {
		return Proof{}, fmt.Errorf("generating blinders: %s", err)
	}

	B_a, err := (&bls12381.G1Jac{}).MultiExp(G, r, common.MultiExpConf)
	if err != nil {
		return Proof{}, fmt.Errorf("computing B_a: %s", err)
	}
	B_t, err := (&bls12381.G1Jac{}).MultiExp(T, r, common.MultiExpConf)
	if err != nil {
		return Proof{}, fmt.Errorf("computing B_t: %s", err)
	}
	B_u, err := (&bls12381.G1Jac{}).MultiExp(U, r, common.MultiExpConf)
	if err != nil {
		return Proof{}, fmt.Errorf("computing B_u: %s", err)
	}

	transcript.AppendPoints([]byte("same_msm_step1"), A, Z_t, Z_u)
	uniontTU := make([]*bls12381.G1Affine, 0, len(T)+len(U))
	for i := range T {
		uniontTU = append(uniontTU, &T[i])
	}
	for i := range U {
		uniontTU = append(uniontTU, &U[i])
	}
	transcript.AppendPointsAffine([]byte("same_msm_step1"), uniontTU...)
	transcript.AppendPoints([]byte("same_msm_step1"), B_a, B_t, B_u)
	alpha := transcript.GetChallenge([]byte("same_msm_alpha"))

	for i := range x {
		x[i].Add(&r[i], (&fr.Element{}).Mul(&x[i], &alpha))
	}

	for len(x) > 1 {
		n /= 2

		x_L, x_R := common.SplitAt(x, n)
		T_L, T_R := common.SplitAt(T, n)
		U_L, U_R := common.SplitAt(U, n)
		G_L, G_R := common.SplitAt(G, n)

		L_A, err := (&bls12381.G1Jac{}).MultiExp(G_R, x_L, common.MultiExpConf)
		if err != nil {
			return Proof{}, fmt.Errorf("computing L_A: %s", err)
		}
		L_T, err := (&bls12381.G1Jac{}).MultiExp(T_R, x_L, common.MultiExpConf)
		if err != nil {
			return Proof{}, fmt.Errorf("computing L_T: %s", err)
		}
		L_U, err := (&bls12381.G1Jac{}).MultiExp(U_R, x_L, common.MultiExpConf)
		if err != nil {
			return Proof{}, fmt.Errorf("computing L_U: %s", err)
		}
		R_A, err := (&bls12381.G1Jac{}).MultiExp(G_L, x_R, common.MultiExpConf)
		if err != nil {
			return Proof{}, fmt.Errorf("computing R_A: %s", err)
		}
		R_T, err := (&bls12381.G1Jac{}).MultiExp(T_L, x_R, common.MultiExpConf)
		if err != nil {
			return Proof{}, fmt.Errorf("computing R_T: %s", err)
		}
		R_U, err := (&bls12381.G1Jac{}).MultiExp(U_L, x_R, common.MultiExpConf)
		if err != nil {
			return Proof{}, fmt.Errorf("computing R_U: %s", err)
		}

		vec_L_A = append(vec_L_A, *L_A)
		vec_L_T = append(vec_L_T, *L_T)
		vec_L_U = append(vec_L_U, *L_U)
		vec_R_A = append(vec_R_A, *R_A)
		vec_R_T = append(vec_R_T, *R_T)
		vec_R_U = append(vec_R_U, *R_U)

		transcript.AppendPoints([]byte("same_msm_loop"), L_A, L_T, L_U, R_A, R_T, R_U)
		gamma := transcript.GetChallenge([]byte("same_msm_gamma"))
		gamma_inv := (&fr.Element{}).Inverse(&gamma)
		if gamma_inv.Equal(&gamma) {
			return Proof{}, fmt.Errorf("gamma is not invertible")
		}

		// Fold vectors and basis
		for i := 0; i < int(n); i++ {
			gammaBigInt := common.FrToBigInt(&gamma)
			x_L[i].Add(&x_L[i], (&fr.Element{}).Mul(gamma_inv, &x_R[i]))
			T_L[i].Add(&T_L[i], (&bls12381.G1Affine{}).ScalarMultiplication(&T_R[i], gammaBigInt))
			U_L[i].Add(&U_L[i], (&bls12381.G1Affine{}).ScalarMultiplication(&U_R[i], gammaBigInt))
			G_L[i].Add(&G_L[i], (&bls12381.G1Affine{}).ScalarMultiplication(&G_R[i], gammaBigInt))
		}
		x = x_L
		T = T_L
		U = U_L
		G = G_L
	}

	return Proof{
		B_a: B_a,
		B_t: B_t,
		B_u: B_u,
		L_A: vec_L_A,
		L_T: vec_L_T,
		L_U: vec_L_U,
		R_A: vec_R_A,
		R_T: vec_R_T,
		R_U: vec_R_U,
		x:   x[0],
	}, nil
}

func Verify(
	proof *Proof,
	G []bls12381.G1Affine,
	A *bls12381.G1Jac,
	Z_t *bls12381.G1Jac,
	Z_u *bls12381.G1Jac,
	T []bls12381.G1Affine,
	U []bls12381.G1Affine,
	transcript *transcript.Transcript,
	msmacc *msmaccumulator.MsmAccumulator,
	rand *common.Rand,
) (bool, error) {
	n := len(T)

	transcript.AppendPoints([]byte("same_msm_step1"), A, Z_t, Z_u)
	TU := make([]*bls12381.G1Affine, len(T)+len(U))
	for i := 0; i < len(T); i++ {
		TU[i] = &T[i]
	}
	for i := 0; i < len(U); i++ {
		TU[i+len(T)] = &U[i]
	}
	transcript.AppendPointsAffine([]byte("same_msm_step1"), TU...)
	transcript.AppendPoints([]byte("same_msm_step1"), proof.B_a, proof.B_t, proof.B_u)
	alpha := transcript.GetChallenge([]byte("same_msm_alpha"))

	gamma, gamma_inv, s, err := unfoldedScalars(proof, n, transcript)
	if err != nil {
		return false, fmt.Errorf("computing verification scalars: %s", err)
	}

	xtimess := make([]fr.Element, len(s))
	for i := 0; i < len(s); i++ {
		xtimess[i].Mul(&proof.x, &s[i])
	}

	var A_a, Z_t_a, Z_u_a bls12381.G1Jac
	A_a.Set(proof.B_a)
	A_a.AddAssign((&bls12381.G1Jac{}).ScalarMultiplication(A, common.FrToBigInt(&alpha)))
	Z_t_a.Set(proof.B_t)
	Z_t_a.AddAssign((&bls12381.G1Jac{}).ScalarMultiplication(Z_t, common.FrToBigInt(&alpha)))
	Z_u_a.Set(proof.B_u)
	Z_u_a.AddAssign((&bls12381.G1Jac{}).ScalarMultiplication(Z_u, common.FrToBigInt(&alpha)))

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
			[]byte("same_msm_loop"),
			&proof.L_A[i],
			&proof.L_T[i],
			&proof.L_U[i],
			&proof.R_A[i],
			&proof.R_T[i],
			&proof.R_U[i],
		)
		challenges = append(challenges, transcript.GetChallenge([]byte("same_msm_gamma")))
	}

	vec_s := make([]fr.Element, 0, n)
	for i := 0; i < n; i++ {
		tmp := fr.One()
		for k := lg_n - 1; k >= 0; k-- {
			bit := i&(1<<(lg_n-k-1)) > 0
			if bit {
				fmt.Printf("i: %d, j: %d, bitstring[i][j]: %d\n", i, lg_n-k, k)
				tmp.Mul(&tmp, &challenges[k])
			}
		}
		vec_s = append(vec_s, tmp)
	}

	return challenges, fr.BatchInvert(challenges), vec_s, nil
}
