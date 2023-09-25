package curdleproof

import (
	"fmt"
	"io"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/group"
	"github.com/jsign/curdleproofs/samemultiscalarargument"
	"github.com/jsign/curdleproofs/samepermutationargument"
	"github.com/jsign/curdleproofs/samescalarargument"
	"github.com/jsign/curdleproofs/transcript"
)

var (
	labelTranscript = []byte("curdleproofs")
	labelStep1      = []byte("curdleproofs_step1")
	labelVecA       = []byte("curdleproofs_vec_a")

	zeroPoint = bls12381.G1Affine{}
	zeroFr    = fr.Element{}
)

type Proof struct {
	A                    group.Element
	T                    group.GroupCommitment
	U                    group.GroupCommitment
	R                    group.Element
	S                    group.Element
	proofSamePermutation samepermutationargument.Proof
	proofSameScalar      samescalarargument.Proof
	proofSameMultiscalar samemultiscalarargument.Proof
}

func Prove(
	g group.Group,

	crs CRS,
	Rs []group.Element,
	Ss []group.Element,
	Ts []group.Element,
	Us []group.Element,
	M group.Element,
	perm []uint32,
	k fr.Element,
	rs_m []fr.Element,
	rand *common.Rand,
) (Proof, error) {
	transcript := transcript.New(labelTranscript)

	// Step 1
	transcript.AppendGroupElements(labelStep1, Rs...)
	transcript.AppendGroupElements(labelStep1, Ss...)
	transcript.AppendGroupElements(labelStep1, Ts...)
	transcript.AppendGroupElements(labelStep1, Us...)
	transcript.AppendGroupElements(labelStep1, M)
	as := transcript.GetAndAppendChallenges(labelVecA, len(Rs))

	// Step 2
	rs_a, err := rand.GetFrs(common.N_BLINDERS - 2)
	if err != nil {
		return Proof{}, fmt.Errorf("getting rs_a: %s", err)
	}

	rs_a_prime := make([]fr.Element, 0, len(rs_a)+1+1)
	rs_a_prime = append(rs_a_prime, rs_a...)
	rs_a_prime = append(rs_a_prime, zeroFr, zeroFr)

	perm_as := common.Permute(as, perm)

	A, A_L, A_R := g.CreateElement(), g.CreateElement(), g.CreateElement()
	if _, err := A_L.MultiExp(crs.Gs, perm_as); err != nil {
		return Proof{}, fmt.Errorf("computing A_L: %s", err)
	}
	if _, err := A_R.MultiExp(crs.Hs, rs_a_prime); err != nil {
		return Proof{}, fmt.Errorf("computing A_R: %s", err)
	}
	A.Set(A_L).AddAssign(A_R)

	proofSamePerm, err := samepermutationargument.Prove(
		g,
		samepermutationargument.CRS{
			Gs: crs.Gs,
			Hs: crs.Hs,
			H:  crs.H,
		},
		A,
		M,
		as,
		perm,
		rs_a_prime,
		rs_m,
		transcript,
		rand,
	)
	if err != nil {
		return Proof{}, fmt.Errorf("proving same permutation: %s", err)
	}

	// Step 3
	r_t, err := rand.GetFr()
	if err != nil {
		return Proof{}, fmt.Errorf("getting random r_t: %s", err)
	}
	r_u, err := rand.GetFr()
	if err != nil {
		return Proof{}, fmt.Errorf("getting random r_u: %s", err)
	}
	R := g.CreateElement()
	if _, err := R.MultiExp(Rs, as); err != nil {
		return Proof{}, fmt.Errorf("computing R: %s", err)
	}
	S := g.CreateElement()
	if _, err := S.MultiExp(Ss, as); err != nil {
		return Proof{}, fmt.Errorf("computing S: %s", err)
	}

	tmp := g.CreateElement()
	tmp.ScalarMultiplication(R, k)
	T := group.NewGroupCommitment(g, crs.Gt, crs.H, tmp, r_t)
	tmp.ScalarMultiplication(S, k)
	U := group.NewGroupCommitment(g, crs.Gu, crs.H, tmp, r_u)

	// TODO(jsign): enforce assumption in callees about mutation of parameters.
	proofSameScalar, err := samescalarargument.Prove(
		g,
		samescalarargument.CRS{
			Gt: crs.Gt,
			Gu: crs.Gu,
			H:  crs.H,
		},
		R,
		S,
		T,
		U,
		k,
		r_t,
		r_u,
		transcript,
		rand,
	)
	if err != nil {
		return Proof{}, fmt.Errorf("proving same scalar: %s", err)
	}

	// Step 4
	A_prime := g.CreateElement()
	A_prime.Set(A)
	A_prime.AddAssign(T.T_1)
	A_prime.AddAssign(U.T_1)

	G := make([]group.Element, len(crs.Gs)+(common.N_BLINDERS-2)+1+1)
	for i := range crs.Gs {
		G[i] = g.CreateElement()
		G[i].Set(crs.Gs[i])
	}
	for i := 0; i < len(crs.Hs)-2; i++ {
		G[i+len(crs.Gs)] = g.CreateElement()
		G[i+len(crs.Gs)].Set(crs.Hs[i])
	}
	G[len(G)-2] = g.CreateElement()
	G[len(G)-2].Set(crs.Gt)
	G[len(G)-1] = g.CreateElement()
	G[len(G)-1].Set(crs.Gu)

	T_prime := make([]group.Element, len(Ts)+2+1+1)
	for i := range Ts {
		T_prime[i] = g.CreateElement()
		T_prime[i].Set(Ts[i])
	}
	T_prime[len(T_prime)-4] = g.CreateElement()
	T_prime[len(T_prime)-3] = g.CreateElement()
	T_prime[len(T_prime)-2] = g.CreateElement()
	T_prime[len(T_prime)-2].Set(crs.H)
	T_prime[len(T_prime)-1] = g.CreateElement()

	U_prime := make([]group.Element, len(Us)+2+1+1)
	for i := range Us {
		U_prime[i] = g.CreateElement()
		U_prime[i].Set(Us[i])
	}
	U_prime[len(U_prime)-4] = g.CreateElement()
	U_prime[len(U_prime)-3] = g.CreateElement()
	U_prime[len(U_prime)-2] = g.CreateElement()
	U_prime[len(U_prime)-1] = g.CreateElement()
	U_prime[len(U_prime)-1].Set(crs.H)

	x := make([]fr.Element, 0, len(perm_as)+len(rs_a)+1+1)
	x = append(x, perm_as...)
	x = append(x, rs_a...)
	x = append(x, r_t, r_u)

	proofSameMultiscalar, err := samemultiscalarargument.Prove(
		g,
		G,
		A_prime,
		T.T_2,
		U.T_2,
		T_prime,
		U_prime,
		x,
		transcript,
		rand,
	)
	if err != nil {
		return Proof{}, fmt.Errorf("proving same multiscalar: %s", err)
	}

	return Proof{
		A,
		T,
		U,
		R,
		S,
		proofSamePerm,
		proofSameScalar,
		proofSameMultiscalar,
	}, nil
}

func Verify(
	g group.Group,

	proof Proof,
	crs CRS,
	Rs []group.Element,
	Ss []group.Element,
	Ts []group.Element,
	Us []group.Element,
	M group.Element,
	rand *common.Rand,
) (bool, error) {
	transcript := transcript.New(labelTranscript)
	msmAccumulator := group.NewMsmAccumulator(g)

	// Make sure that randomizer was not the zero element (and wiped out the ciphertexts)
	if Ts[0].Equal(g.CreateElement()) {
		return false, fmt.Errorf("randomizer is zero")
	}

	// Step 1
	transcript.AppendGroupElements(labelStep1, Rs...)
	transcript.AppendGroupElements(labelStep1, Ss...)
	transcript.AppendGroupElements(labelStep1, Ts...)
	transcript.AppendGroupElements(labelStep1, Us...)
	transcript.AppendGroupElements(labelStep1, M)
	as := transcript.GetAndAppendChallenges(labelVecA, len(Rs))

	// Step 2
	ok, err := samepermutationargument.Verify(
		g,
		proof.proofSamePermutation,
		samepermutationargument.CRS{
			Gs: crs.Gs,
			Hs: crs.Hs,
			H:  crs.H,
		},
		crs.Gsum,
		crs.Hsum,
		proof.A,
		M,
		as,
		common.N_BLINDERS,
		transcript,
		msmAccumulator,
		rand,
	)
	if err != nil {
		return false, fmt.Errorf("verifying same permutation: %s", err)
	}
	if !ok {
		return false, nil
	}

	// Step 3
	if ok := samescalarargument.Verify(
		g,
		proof.proofSameScalar,
		samescalarargument.CRS{
			Gt: crs.Gt,
			Gu: crs.Gu,
			H:  crs.H,
		},
		proof.R,
		proof.S,
		proof.T,
		proof.U,
		transcript,
	); !ok {
		return false, nil
	}

	// Step 4
	Aprime := g.CreateElement()
	Aprime.Set(proof.A)
	Aprime.AddAssign(proof.T.T_1).AddAssign(proof.U.T_1)

	Gs := make([]group.Element, len(crs.Gs)+(common.N_BLINDERS-2)+1+1)
	for i := range crs.Gs {
		Gs[i] = g.CreateElement()
		Gs[i].Set(crs.Gs[i])
	}
	for i := 0; i < len(crs.Hs)-2; i++ {
		Gs[i+len(crs.Gs)] = g.CreateElement()
		Gs[i+len(crs.Gs)].Set(crs.Hs[i])
	}
	Gs[len(Gs)-2] = g.CreateElement()
	Gs[len(Gs)-2].Set(crs.Gt)
	Gs[len(Gs)-1] = g.CreateElement()
	Gs[len(Gs)-1].Set(crs.Gu)

	Tsprime := make([]group.Element, len(Ts)+2+1+1)
	for i := range Ts {
		Tsprime[i] = g.CreateElement()
		Tsprime[i].Set(Ts[i])
	}
	Tsprime[len(Tsprime)-4] = g.CreateElement()
	Tsprime[len(Tsprime)-3] = g.CreateElement()
	Tsprime[len(Tsprime)-2] = g.CreateElement()
	Tsprime[len(Tsprime)-2] = crs.H
	Tsprime[len(Tsprime)-1] = g.CreateElement()

	Usprime := make([]group.Element, len(Us)+2+1+1)
	for i := range Us {
		Usprime[i] = g.CreateElement()
		Usprime[i].Set(Us[i])
	}
	Usprime[len(Usprime)-4] = g.CreateElement()
	Usprime[len(Usprime)-3] = g.CreateElement()
	Usprime[len(Usprime)-2] = g.CreateElement()
	Usprime[len(Usprime)-1] = g.CreateElement()
	Usprime[len(Usprime)-1] = crs.H

	ok, err = samemultiscalarargument.Verify(
		g,
		proof.proofSameMultiscalar,
		Gs,
		Aprime,
		proof.T.T_2,
		proof.U.T_2,
		Tsprime,
		Usprime,
		transcript,
		msmAccumulator,
		rand,
	)
	if err != nil {
		return false, fmt.Errorf("verifying same multiscalar: %s", err)
	}
	if !ok {
		return false, nil
	}

	if err := msmAccumulator.AccumulateCheck(proof.R, as, Rs, rand); err != nil {
		return false, fmt.Errorf("msm accumulator check R, as, Rs: %s", err)
	}
	if err := msmAccumulator.AccumulateCheck(proof.S, as, Ss, rand); err != nil {
		return false, fmt.Errorf("msm accumulator check S, as, Ss: %s", err)
	}

	ok, err = msmAccumulator.Verify()
	if err != nil {
		return false, fmt.Errorf("verifying msm accumulator: %s", err)
	}
	return ok, nil
}

func (p *Proof) FromReader(r io.Reader) error {
	// var tmp bls12381.G1Affine
	// d := bls12381.NewDecoder(r)

	// if err := d.Decode(&tmp); err != nil {
	// 	return fmt.Errorf("decoding A: %s", err)
	// }
	// p.A.FromAffine(&tmp)

	// if err := p.T.FromReader(r); err != nil {
	// 	return fmt.Errorf("decoding T: %s", err)
	// }
	// if err := p.U.FromReader(r); err != nil {
	// 	return fmt.Errorf("decoding U: %s", err)
	// }
	// if err := d.Decode(&tmp); err != nil {
	// 	return fmt.Errorf("decoding R: %s", err)
	// }
	// p.R.FromAffine(&tmp)

	// if err := d.Decode(&tmp); err != nil {
	// 	return fmt.Errorf("decoding S: %s", err)
	// }
	// p.S.FromAffine(&tmp)

	// if err := p.proofSamePermutation.FromReader(r); err != nil {
	// 	return fmt.Errorf("decoding proofSamePermutation: %s", err)
	// }
	// if err := p.proofSameScalar.FromReader(r); err != nil {
	// 	return fmt.Errorf("decoding proofSameScalar: %s", err)
	// }
	// if err := p.proofSameMultiscalar.FromReader(r); err != nil {
	// 	return fmt.Errorf("decoding proofSameMultiscalar: %s", err)
	// }

	return nil
}

func (p *Proof) Serialize(w io.Writer) error {
	// e := bls12381.NewEncoder(w)
	// ars := bls12381.BatchJacobianToAffineG1([]bls12381.G1Jac{p.A, p.R, p.S})
	// if err := e.Encode(&ars[0]); err != nil {
	// 	panic(fmt.Errorf("encoding A: %s", err))
	// }
	// if err := p.T.Serialize(w); err != nil {
	// 	return fmt.Errorf("encoding T: %s", err)
	// }
	// if err := p.U.Serialize(w); err != nil {
	// 	return fmt.Errorf("encoding U: %s", err)
	// }
	// if err := e.Encode(&ars[1]); err != nil {
	// 	return fmt.Errorf("encoding R: %s", err)
	// }
	// if err := e.Encode(&ars[2]); err != nil {
	// 	return fmt.Errorf("encoding S: %s", err)
	// }
	// if err := p.proofSamePermutation.Serialize(w); err != nil {
	// 	return fmt.Errorf("encoding proofSamePermutation: %s", err)
	// }
	// if err := p.proofSameScalar.Serialize(w); err != nil {
	// 	return fmt.Errorf("encoding proofSameScalar: %s", err)
	// }
	// if err := p.proofSameMultiscalar.Serialize(w); err != nil {
	// 	return fmt.Errorf("encoding proofSameMultiscalar: %s", err)
	// }

	return nil
}
