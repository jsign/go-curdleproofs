package curdleproof

import (
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/groupcommitment"
	"github.com/jsign/curdleproofs/msmaccumulator"
	"github.com/jsign/curdleproofs/samemultiscalarargument"
	"github.com/jsign/curdleproofs/samepermutationargument"
	"github.com/jsign/curdleproofs/samescalarargument"
	"github.com/jsign/curdleproofs/transcript"
)

const (
	N_BLINDERS = 4
)

var (
	zero = bls12381.G1Affine{}
)

type Proof struct {
	A                    bls12381.G1Jac
	T                    groupcommitment.GroupCommitment
	U                    groupcommitment.GroupCommitment
	R                    bls12381.G1Jac
	S                    bls12381.G1Jac
	proofSamePermutation samepermutationargument.Proof
	proofSameScalar      samescalarargument.Proof
	proofSameMultiscalar samemultiscalarargument.Proof
}

func Prove(
	crs CRS,
	Rs []bls12381.G1Affine,
	Ss []bls12381.G1Affine,
	Ts []bls12381.G1Affine,
	Us []bls12381.G1Affine,
	M bls12381.G1Jac,
	permutation []uint32,
	k fr.Element,
	rs_m []fr.Element,
	rand *common.Rand,
) (Proof, error) {
	//         // Number of non-blinder elements used in this proof
	//         let ell = vec_R.len();

	transcript := transcript.New([]byte("curdleproofs"))

	// Step 1
	transcript.AppendPointsAffine([]byte("curdleproofs_step1"), Rs...)
	transcript.AppendPointsAffine([]byte("curdleproofs_step1"), Ss...)
	transcript.AppendPointsAffine([]byte("curdleproofs_step1"), Ts...)
	transcript.AppendPointsAffine([]byte("curdleproofs_step1"), Us...)
	transcript.AppendPoints([]byte("curdleproofs_step1"), &M)
	as := transcript.GetAndAppendChallenges([]byte("curdleproofs_vec_a"), len(Rs))

	// Step 2
	rs_a, err := rand.GetFrs(N_BLINDERS - 2)
	if err != nil {
		return Proof{}, fmt.Errorf("getting random frs: %s", err)
	}

	rs_a_prime := make([]fr.Element, len(rs_a)+1)
	copy(rs_a_prime, rs_a)

	perm_as := common.Permute(as, permutation)
	var A, A_L, A_R bls12381.G1Jac
	if _, err := A_L.MultiExp(crs.Gs, perm_as, common.MultiExpConf); err != nil {
		return Proof{}, fmt.Errorf("computing A_L: %s", err)
	}
	if _, err := A_R.MultiExp(crs.Hs, rs_a_prime, common.MultiExpConf); err != nil {
		return Proof{}, fmt.Errorf("computing A_R: %s", err)
	}
	A.Set(&A_L).AddAssign(&A_R)

	proofSamePerm, err := samepermutationargument.Prove(
		samepermutationargument.CRS{
			Gs: crs.Gs,
			Hs: crs.Hs,
			H:  crs.H,
		},
		A,
		M,
		as,
		permutation,
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
	var R bls12381.G1Jac
	if _, err := R.MultiExp(Rs, as, common.MultiExpConf); err != nil {
		return Proof{}, fmt.Errorf("computing R: %s", err)
	}
	var S bls12381.G1Jac
	if _, err := S.MultiExp(Ss, as, common.MultiExpConf); err != nil {
		return Proof{}, fmt.Errorf("computing S: %s", err)
	}

	var tmp bls12381.G1Jac
	tmp.ScalarMultiplication(&R, common.FrToBigInt(&k))
	T := groupcommitment.New(&crs.Gt, &crs.H, &tmp, &r_t)
	tmp.ScalarMultiplication(&S, common.FrToBigInt(&k))
	U := groupcommitment.New(&crs.Gu, &crs.H, &tmp, &r_u)

	// TODO(jsign): enforce assumption in callees about mutation of parameters.
	proofSameScalar, err := samescalarargument.Prove(
		&samescalarargument.CRS{
			Gt: crs.Gt,
			Gu: crs.Gu,
			H:  crs.H,
		},
		&R,
		&S,
		T,
		U,
		&k,
		&r_t,
		&r_u,
		transcript,
		rand,
	)
	if err != nil {
		return Proof{}, fmt.Errorf("proving same scalar: %s", err)
	}

	// Step 4
	A_prime := A
	A_prime.AddAssign(&T.T_1)
	A_prime.AddAssign(&U.T_1)

	G := make([]bls12381.G1Affine, 0, len(crs.Gs)+(N_BLINDERS-2)+1+1)
	G = append(G, crs.Gs...)
	G = append(G, crs.Hs[:N_BLINDERS-2]...)
	gxaffine := bls12381.BatchJacobianToAffineG1([]bls12381.G1Jac{crs.Gt, crs.Gu})
	G = append(G, gxaffine...)

	T_prime := make([]bls12381.G1Affine, 0, len(Ts)+2+1+1)
	T_prime = append(T_prime, Ts...)
	var crsHAffine bls12381.G1Affine
	crsHAffine.FromJacobian(&crs.H)
	T_prime = append(T_prime, zero, zero, crsHAffine, zero)

	U_prime := make([]bls12381.G1Affine, 0, len(Us)+2+1+1)
	U_prime = append(U_prime, Us...)
	U_prime = append(U_prime, zero, zero, zero)
	U_prime = append(U_prime, crsHAffine)

	x := make([]fr.Element, 0, len(perm_as)+len(rs_a)+1+1)
	x = append(x, perm_as...)
	x = append(x, rs_a...)
	x = append(x, r_t, r_u)

	proofSameMultiscalar, err := samemultiscalarargument.Prove(
		G,
		&A_prime,
		&T.T_2,
		&U.T_2,
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
	proof Proof,
	crs CRS,
	Rs []bls12381.G1Affine,
	Ss []bls12381.G1Affine,
	Ts []bls12381.G1Affine,
	Us []bls12381.G1Affine,
	M bls12381.G1Jac,
	rand *common.Rand,
) (bool, error) {
	transcript := transcript.New([]byte("curdleproofs"))
	msmAccumulator := msmaccumulator.New()

	// Make sure that randomizer was not the zero element (and wiped out the ciphertexts)
	if Ts[0].IsInfinity() {
		return false, fmt.Errorf("randomizer is zero")
	}

	// Step 1
	transcript.AppendPointsAffine([]byte("curdleproofs_step1"), Rs...)
	transcript.AppendPointsAffine([]byte("curdleproofs_step1"), Ss...)
	transcript.AppendPointsAffine([]byte("curdleproofs_step1"), Ts...)
	transcript.AppendPointsAffine([]byte("curdleproofs_step1"), Us...)
	transcript.AppendPoints([]byte("curdleproofs_step1"), &M)
	as := transcript.GetAndAppendChallenges([]byte("curdleproofs_vec_a"), len(Rs))

	// Step 2
	ok, err := samepermutationargument.Verify(
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
		N_BLINDERS,
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
	Aprime := proof.A
	Aprime.AddAssign(&proof.T.T_1).AddAssign(&proof.U.T_1)

	Gs := make([]bls12381.G1Affine, 0, len(crs.Gs)+(N_BLINDERS-2)+1+1)
	Gs = append(Gs, crs.Gs...)
	Gs = append(Gs, crs.Hs[:N_BLINDERS-2]...)
	gaffs := bls12381.BatchJacobianToAffineG1([]bls12381.G1Jac{crs.Gt, crs.Gu})
	Gs = append(Gs, gaffs...)

	Tsprime := make([]bls12381.G1Affine, 0, len(Ts)+2+1+1)
	Tsprime = append(Tsprime, Ts...)
	var HAff bls12381.G1Affine
	HAff.FromJacobian(&crs.H)
	Tsprime = append(Tsprime, zero, zero, HAff, zero)

	Usprime := make([]bls12381.G1Affine, 0, len(Us)+2+1+1)
	Usprime = append(Usprime, Us...)
	Usprime = append(Usprime, zero, zero, zero, HAff)

	ok, err = samemultiscalarargument.Verify(
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

	msmAccumulator.AccumulateCheck(proof.R, as, Rs, rand)
	msmAccumulator.AccumulateCheck(proof.S, as, Ss, rand)

	ok, err = msmAccumulator.Verify()
	if err != nil {
		return false, fmt.Errorf("verifying msm accumulator: %s", err)
	}
	return ok, nil
}
