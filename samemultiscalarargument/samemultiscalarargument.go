package samemultiscalarargument

import (
	"fmt"
	"io"
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/group"
	"github.com/jsign/curdleproofs/transcript"
)

var (
	labelStep1 = []byte("same_msm_step1")
	labelAlpha = []byte("same_msm_alpha")
	labelLoop  = []byte("same_msm_loop")
	labelGamma = []byte("same_msm_gamma")
)

type Proof struct {
	B_a group.Element
	B_t group.Element
	B_u group.Element

	L_A []group.Element
	L_T []group.Element
	L_U []group.Element
	R_A []group.Element
	R_T []group.Element
	R_U []group.Element

	x fr.Element
}

func Prove(
	g group.Group,

	G []group.Element,
	A group.Element,
	Z_t group.Element,
	Z_u group.Element,
	T []group.Element,
	U []group.Element,
	x []fr.Element,
	transcript *transcript.Transcript,
	rand *common.Rand,
) (Proof, error) {
	n := uint(len(x))
	m := bits.Len(n) - 1

	L_Ts := make([]group.Element, 0, m)
	R_Ts := make([]group.Element, 0, m)
	L_Us := make([]group.Element, 0, m)
	R_Us := make([]group.Element, 0, m)
	L_As := make([]group.Element, 0, m)
	R_As := make([]group.Element, 0, m)

	r, err := rand.GetFrs(int(n))
	if err != nil {
		return Proof{}, fmt.Errorf("generating blinders: %s", err)
	}

	B_a, B_t, B_u := g.CreateElement(), g.CreateElement(), g.CreateElement()
	if _, err := B_a.MultiExp(G, r); err != nil {
		return Proof{}, fmt.Errorf("computing B_a: %s", err)
	}
	if _, err := B_t.MultiExp(T, r); err != nil {
		return Proof{}, fmt.Errorf("computing B_t: %s", err)
	}
	if _, err := B_u.MultiExp(U, r); err != nil {
		return Proof{}, fmt.Errorf("computing B_u: %s", err)
	}

	transcript.AppendGroupElements(labelStep1, A, Z_t, Z_u)
	transcript.AppendGroupElements(labelStep1, T...)
	transcript.AppendGroupElements(labelStep1, U...)
	transcript.AppendGroupElements(labelStep1, B_a, B_t, B_u)
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

		L_A, L_T, L_U, R_A, R_T, R_U := g.CreateElement(), g.CreateElement(), g.CreateElement(), g.CreateElement(), g.CreateElement(), g.CreateElement()
		if _, err := L_A.MultiExp(G_R, x_L); err != nil {
			return Proof{}, fmt.Errorf("computing L_A: %s", err)
		}
		if _, err := L_T.MultiExp(T_R, x_L); err != nil {
			return Proof{}, fmt.Errorf("computing L_T: %s", err)
		}
		if _, err := L_U.MultiExp(U_R, x_L); err != nil {
			return Proof{}, fmt.Errorf("computing L_U: %s", err)
		}
		if _, err := R_A.MultiExp(G_L, x_R); err != nil {
			return Proof{}, fmt.Errorf("computing R_A: %s", err)
		}
		if _, err := R_T.MultiExp(T_L, x_R); err != nil {
			return Proof{}, fmt.Errorf("computing R_T: %s", err)
		}
		if _, err := R_U.MultiExp(U_L, x_R); err != nil {
			return Proof{}, fmt.Errorf("computing R_U: %s", err)
		}

		L_As = append(L_As, L_A)
		L_Ts = append(L_Ts, L_T)
		L_Us = append(L_Us, L_U)
		R_As = append(R_As, R_A)
		R_Ts = append(R_Ts, R_T)
		R_Us = append(R_Us, R_U)

		transcript.AppendGroupElements(labelLoop, L_A, L_T, L_U, R_A, R_T, R_U)
		gamma := transcript.GetAndAppendChallenge(labelGamma)
		if gamma.IsZero() {
			return Proof{}, fmt.Errorf("gamma is zero")
		}
		var gamma_inv fr.Element
		gamma_inv.Inverse(&gamma)

		// Fold vectors and basis
		for i := 0; i < int(n); i++ {
			tmp := g.CreateElement()
			x_L[i].Add(&x_L[i], (&fr.Element{}).Mul(&gamma_inv, &x_R[i]))
			T_L[i].Add(T_L[i], tmp.ScalarMultiplication(T_R[i], gamma))
			U_L[i].Add(U_L[i], tmp.ScalarMultiplication(U_R[i], gamma))
			G_L[i].Add(G_L[i], tmp.ScalarMultiplication(G_R[i], gamma))
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
	g group.Group,

	proof Proof,
	G []group.Element,
	A group.Element,
	Z_t group.Element,
	Z_u group.Element,
	T []group.Element,
	U []group.Element,
	transcript *transcript.Transcript,
	msmacc *group.MsmAccumulator,
	rand *common.Rand,
) (bool, error) {
	n := len(T)

	transcript.AppendGroupElements(labelStep1, A, Z_t, Z_u)
	transcript.AppendGroupElements(labelStep1, T...)
	transcript.AppendGroupElements(labelStep1, U...)
	transcript.AppendGroupElements(labelStep1, proof.B_a, proof.B_t, proof.B_u)
	alpha := transcript.GetAndAppendChallenge(labelAlpha)

	gamma, gamma_inv, s, err := unfoldedScalars(&proof, n, transcript)
	if err != nil {
		return false, fmt.Errorf("computing verification scalars: %s", err)
	}

	xtimess := make([]fr.Element, len(s))
	for i := 0; i < len(s); i++ {
		xtimess[i].Mul(&proof.x, &s[i])
	}

	A_a, Z_t_a, Z_u_a := g.CreateElement(), g.CreateElement(), g.CreateElement()
	tmp := g.CreateElement()
	A_a.Set(proof.B_a).AddAssign(tmp.ScalarMultiplication(A, alpha))
	Z_t_a.Set(proof.B_t).AddAssign(tmp.ScalarMultiplication(Z_t, alpha))
	Z_u_a.Set(proof.B_u).AddAssign(tmp.ScalarMultiplication(Z_u, alpha))

	l, p, r := g.CreateElement(), g.CreateElement(), g.CreateElement()
	if _, err := l.MultiExp(proof.L_A, gamma); err != nil {
		return false, fmt.Errorf("computing point_lhs msm: %s", err)
	}
	if _, err := r.MultiExp(proof.R_A, gamma_inv); err != nil {
		return false, fmt.Errorf("computing point_lhs msm: %s", err)
	}
	p.Set(A_a).AddAssign(l).AddAssign(r)

	tmpCheck := g.CreateElement()
	if _, err := tmpCheck.MultiExp(G, xtimess); err != nil {
		panic(err)
	}
	if !tmpCheck.Equal(p) {
		panic("wrong")
	}
	if err := msmacc.AccumulateCheck(p, xtimess, G, rand); err != nil {
		return false, fmt.Errorf("accumulating msm 1: %s", err)
	}
	if _, err := l.MultiExp(proof.L_T, gamma); err != nil {
		return false, fmt.Errorf("computing point_lhs msm: %s", err)
	}
	if _, err := r.MultiExp(proof.R_T, gamma_inv); err != nil {
		return false, fmt.Errorf("computing point_lhs msm: %s", err)
	}
	p.Set(Z_t_a).AddAssign(l).AddAssign(r)
	if err := msmacc.AccumulateCheck(p, xtimess, T, rand); err != nil {
		return false, fmt.Errorf("accumulating msm 1: %s", err)
	}

	if _, err := l.MultiExp(proof.L_U, gamma); err != nil {
		return false, fmt.Errorf("computing point_lhs msm: %s", err)
	}
	if _, err := r.MultiExp(proof.R_U, gamma_inv); err != nil {
		return false, fmt.Errorf("computing point_lhs msm: %s", err)
	}
	p.Set(Z_u_a).AddAssign(l).AddAssign(r)
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
		transcript.AppendGroupElements(
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
	// d := bls12381.NewDecoder(r)
	// var tmp bls12381.G1Affine

	// if err := d.Decode(&tmp); err != nil {
	// 	return fmt.Errorf("decoding B_a: %s", err)
	// }
	// p.B_a.FromAffine(&tmp)

	// if err := d.Decode(&tmp); err != nil {
	// 	return fmt.Errorf("decoding B_t: %s", err)
	// }
	// p.B_t.FromAffine(&tmp)

	// if err := d.Decode(&tmp); err != nil {
	// 	return fmt.Errorf("decoding B_u: %s", err)
	// }
	// p.B_u.FromAffine(&tmp)

	// if err := common.DecodeAffineSliceToJac(d, &p.L_A); err != nil {
	// 	return fmt.Errorf("decoding L_A: %s", err)
	// }
	// if err := common.DecodeAffineSliceToJac(d, &p.L_T); err != nil {
	// 	return fmt.Errorf("decoding L_T: %s", err)
	// }
	// if err := common.DecodeAffineSliceToJac(d, &p.L_U); err != nil {
	// 	return fmt.Errorf("decoding L_U: %s", err)
	// }
	// if err := common.DecodeAffineSliceToJac(d, &p.R_A); err != nil {
	// 	return fmt.Errorf("decoding R_A: %s", err)
	// }
	// if err := common.DecodeAffineSliceToJac(d, &p.R_T); err != nil {
	// 	return fmt.Errorf("decoding R_T: %s", err)
	// }
	// if err := common.DecodeAffineSliceToJac(d, &p.R_U); err != nil {
	// 	return fmt.Errorf("decoding R_U: %s", err)
	// }
	// if err := d.Decode(&p.x); err != nil {
	// 	return fmt.Errorf("decoding x: %s", err)
	// }
	return nil
}

func (p *Proof) Serialize(w io.Writer) error {
	// aff_bs := bls12381.BatchJacobianToAffineG1([]bls12381.G1Jac{p.B_a, p.B_t, p.B_u})
	// e := bls12381.NewEncoder(w)
	// if err := e.Encode(&aff_bs[0]); err != nil {
	// 	return fmt.Errorf("encoding B_a: %s", err)
	// }
	// if err := e.Encode(&aff_bs[1]); err != nil {
	// 	return fmt.Errorf("encoding B_t: %s", err)
	// }
	// if err := e.Encode(&aff_bs[2]); err != nil {
	// 	return fmt.Errorf("encoding B_u: %s", err)
	// }
	// affL_A := bls12381.BatchJacobianToAffineG1(p.L_A)
	// if err := e.Encode(affL_A); err != nil {
	// 	return fmt.Errorf("encoding L_A: %s", err)
	// }
	// affL_T := bls12381.BatchJacobianToAffineG1(p.L_T)
	// if err := e.Encode(affL_T); err != nil {
	// 	return fmt.Errorf("encoding L_T: %s", err)
	// }
	// affL_U := bls12381.BatchJacobianToAffineG1(p.L_U)
	// if err := e.Encode(affL_U); err != nil {
	// 	return fmt.Errorf("encoding L_U: %s", err)
	// }
	// affR_A := bls12381.BatchJacobianToAffineG1(p.R_A)
	// if err := e.Encode(affR_A); err != nil {
	// 	return fmt.Errorf("encoding R_A: %s", err)
	// }
	// affR_T := bls12381.BatchJacobianToAffineG1(p.R_T)
	// if err := e.Encode(affR_T); err != nil {
	// 	return fmt.Errorf("encoding R_T: %s", err)
	// }
	// affR_U := bls12381.BatchJacobianToAffineG1(p.R_U)
	// if err := e.Encode(affR_U); err != nil {
	// 	return fmt.Errorf("encoding R_U: %s", err)
	// }
	// if err := e.Encode(&p.x); err != nil {
	// 	return fmt.Errorf("encoding x: %s", err)
	// }
	return nil
}
