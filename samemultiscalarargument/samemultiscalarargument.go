package samemultiscalarargument

import (
	"fmt"
	"math/bits"
	"runtime"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/transcript"
)

var multiExpConf = ecc.MultiExpConfig{NbTasks: runtime.NumCPU()}

type Proof struct {
	B_a *bls12381.G1Affine
	B_t *bls12381.G1Affine
	B_u *bls12381.G1Affine

	L_A []bls12381.G1Affine
	L_T []bls12381.G1Affine
	L_U []bls12381.G1Affine
	R_A []bls12381.G1Affine
	R_T []bls12381.G1Affine
	R_U []bls12381.G1Affine

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

	transcript transcript.Transcript,
	rand common.Rand,
) (Proof, error) {
	n := uint(len(x))
	m := bits.Len(n)

	vec_L_T := make([]bls12381.G1Affine, m)
	vec_R_T := make([]bls12381.G1Affine, m)
	vec_L_U := make([]bls12381.G1Affine, m)
	vec_R_U := make([]bls12381.G1Affine, m)
	vec_L_A := make([]bls12381.G1Affine, m)
	vec_R_A := make([]bls12381.G1Affine, m)

	r, err := common.GenerateBlindersFr(rand, n)
	if err != nil {
		return Proof{}, fmt.Errorf("generating blinders: %s", err)
	}

	B_a, err := (&bls12381.G1Affine{}).MultiExp(G, r, multiExpConf)
	if err != nil {
		return Proof{}, fmt.Errorf("computing B_a: %s", err)
	}
	B_t, err := (&bls12381.G1Affine{}).MultiExp(T, r, multiExpConf)
	if err != nil {
		return Proof{}, fmt.Errorf("computing B_t: %s", err)
	}
	B_u, err := (&bls12381.G1Affine{}).MultiExp(U, r, multiExpConf)
	if err != nil {
		return Proof{}, fmt.Errorf("computing B_u: %s", err)
	}
	transcript.AppendPoints([]byte("same_msm_step1"), &A, &Z_t, &Z_u)
	uniontTU := make([]*bls12381.G1Affine, 0, len(T)+len(U))
	for i := range T {
		uniontTU = append(uniontTU, &T[i])
	}
	for i := range U {
		uniontTU = append(uniontTU, &U[i])
	}
	transcript.AppendPointsAffine([]byte("same_msm_step1"), uniontTU...)
	transcript.AppendPointsAffine([]byte("same_msm_step1"), B_a, B_t, B_u)
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

		L_A, err := (&bls12381.G1Affine{}).MultiExp(G_R, x_L, multiExpConf)
		if err != nil {
			return Proof{}, fmt.Errorf("computing L_A: %s", err)
		}
		L_T, err := (&bls12381.G1Affine{}).MultiExp(T_R, x_L, multiExpConf)
		if err != nil {
			return Proof{}, fmt.Errorf("computing L_T: %s", err)
		}
		L_U, err := (&bls12381.G1Affine{}).MultiExp(U_R, x_L, multiExpConf)
		if err != nil {
			return Proof{}, fmt.Errorf("computing L_U: %s", err)
		}
		R_A, err := (&bls12381.G1Affine{}).MultiExp(G_L, x_R, multiExpConf)
		if err != nil {
			return Proof{}, fmt.Errorf("computing R_A: %s", err)
		}
		R_T, err := (&bls12381.G1Affine{}).MultiExp(T_L, x_R, multiExpConf)
		if err != nil {
			return Proof{}, fmt.Errorf("computing R_T: %s", err)
		}
		R_U, err := (&bls12381.G1Affine{}).MultiExp(U_L, x_R, multiExpConf)
		if err != nil {
			return Proof{}, fmt.Errorf("computing R_U: %s", err)
		}

		vec_L_A = append(vec_L_A, *L_A)
		vec_L_T = append(vec_L_T, *L_T)
		vec_L_U = append(vec_L_U, *L_U)
		vec_R_A = append(vec_R_A, *R_A)
		vec_R_T = append(vec_R_T, *R_T)
		vec_R_U = append(vec_R_U, *R_U)

		transcript.AppendPointsAffine([]byte("same_msm_loop"), L_A, L_T, L_U, R_A, R_T, R_U)
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
