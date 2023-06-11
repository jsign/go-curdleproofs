package grandproductargument

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/innerproductargument"
	"github.com/jsign/curdleproofs/msmaccumulator"
	"github.com/jsign/curdleproofs/transcript"
)

var minusOne fr.Element

func init() {
	one := fr.One()
	minusOne.Neg(&one)
}

type Proof struct {
	C        bls12381.G1Jac
	Rp       fr.Element
	IPAProof innerproductargument.Proof
}

type CRS struct {
	Gs []bls12381.G1Affine
	Hs []bls12381.G1Affine
	H  bls12381.G1Jac
}

func Prove(
	crs CRS,
	B bls12381.G1Jac,
	result fr.Element,
	bs []fr.Element,
	r_bs []fr.Element,
	transcript *transcript.Transcript,
	rand *common.Rand,
) (Proof, error) {
	// Step 1.
	transcript.AppendPoints([]byte("gprod_step1"), &B)
	transcript.AppendScalars([]byte("gprod_step1"), result)
	alpha := transcript.GetAndAppendChallenge([]byte("gprod_alpha"))

	// Step 2.
	cs := make([]fr.Element, len(crs.Gs))
	cs[0] = fr.One()
	for i := 1; i < len(cs); i++ {
		cs[i].Mul(&cs[i-1], &bs[i-1])
	}
	r_cs, err := rand.GetFrs(len(r_bs))
	if err != nil {
		return Proof{}, fmt.Errorf("generate R_Cs: %s", err)
	}
	var C, C_L, C_R bls12381.G1Jac
	if _, err := C_L.MultiExp(crs.Gs, cs, common.MultiExpConf); err != nil {
		return Proof{}, fmt.Errorf("compute C_L: %s", err)
	}
	if _, err := C_R.MultiExp(crs.Hs, r_cs, common.MultiExpConf); err != nil {
		return Proof{}, fmt.Errorf("compute C_R: %s", err)
	}
	C.Set(&C_L).AddAssign(&C_R)

	r_b_plus_alpha := make([]fr.Element, len(r_bs))
	for i := range r_b_plus_alpha {
		r_b_plus_alpha[i].Add(&r_bs[i], &alpha)
	}
	r_p := common.IPA(r_b_plus_alpha, r_cs)
	transcript.AppendPoints([]byte("gprod_step2"), &C)
	transcript.AppendScalars([]byte("gprod_step2"), r_p)
	beta := transcript.GetAndAppendChallenge([]byte("gprod_beta"))
	if beta.IsZero() {
		return Proof{}, fmt.Errorf("beta is zero")
	}
	// Step 3
	var betaInv fr.Element
	betaInv.Inverse(&beta)

	Gs_prime := make([]bls12381.G1Affine, len(crs.Gs))
	tmpBetaInv := betaInv
	for i := range Gs_prime {
		Gs_prime[i].ScalarMultiplication(&crs.Gs[i], common.FrToBigInt(&tmpBetaInv))
		tmpBetaInv.Mul(&tmpBetaInv, &betaInv)
	}
	Hs_prime := make([]bls12381.G1Affine, len(crs.Hs))
	for i := range Hs_prime {
		Hs_prime[i].ScalarMultiplication(&crs.Hs[i], common.FrToBigInt(&tmpBetaInv))
	}
	bs_prime := make([]fr.Element, len(crs.Gs))
	tmpBeta := beta
	for i := range bs_prime {
		bs_prime[i].Mul(&bs[i], &tmpBeta)
		tmpBeta.Mul(&tmpBeta, &beta)
	}

	ds := make([]fr.Element, len(crs.Gs), len(crs.Gs)+len(r_bs))
	tmpBeta = fr.One() // TODO(jsign): prob optimizable, since powers could be calculated in the previous step.
	betaPowers := make([]fr.Element, len(crs.Gs))
	for i := range bs_prime {
		ds[i].Sub(&bs_prime[i], &tmpBeta)
		betaPowers[i].Set(&tmpBeta)
		tmpBeta.Mul(&tmpBeta, &beta)
	}

	r_ds := make([]fr.Element, len(r_b_plus_alpha))
	var betaExpLPlus1 fr.Element
	betaExpLPlus1.Exp(beta, big.NewInt(int64(len(crs.Gs)+1)))
	for i := range r_ds {
		r_ds[i].Mul(&betaExpLPlus1, &r_b_plus_alpha[i])
	}

	alphaBetaExpPlus1 := make([]fr.Element, len(r_bs))
	for i := range alphaBetaExpPlus1 {
		alphaBetaExpPlus1[i].Mul(&alpha, &betaExpLPlus1)
	}
	var D, D_L, D_R bls12381.G1Jac
	if _, err := D_L.MultiExp(Gs_prime, betaPowers, common.MultiExpConf); err != nil {
		return Proof{}, fmt.Errorf("compute D_L: %s", err)
	}
	if _, err := D_R.MultiExp(Hs_prime, alphaBetaExpPlus1, common.MultiExpConf); err != nil {
		return Proof{}, fmt.Errorf("compute D_R: %s", err)
	}
	D.Set(&B).SubAssign(&D_L).AddAssign(&D_R)

	// Step 4
	Gs := make([]bls12381.G1Affine, len(crs.Gs)+len(crs.Hs))
	copy(Gs, crs.Gs)
	copy(Gs[len(crs.Gs):], crs.Hs)

	Gs_prime = append(Gs_prime, Hs_prime...)

	var z, z_L, z_R fr.Element
	z_L.Mul(&r_p, &betaExpLPlus1)
	z_R.Mul(&result, &tmpBeta)
	z.Add(&z_L, &z_R)
	z.Add(&z, &minusOne)

	cs = append(cs, r_cs...)
	ds = append(ds, r_ds...)

	// TODO(jsign): make sanity checks optional.
	ipaC_D := common.IPA(cs, ds)
	if !ipaC_D.Equal(&z) {
		return Proof{}, fmt.Errorf("IPA(C, D) != z")
	}
	var msmG_cs bls12381.G1Jac
	if _, err := msmG_cs.MultiExp(Gs, cs, common.MultiExpConf); err != nil {
		return Proof{}, fmt.Errorf("compute msm(G, c): %s", err)
	}
	if !msmG_cs.Equal(&C) {
		return Proof{}, fmt.Errorf("msm(G, c) != C")
	}
	var msmG_prime_ds bls12381.G1Jac
	if _, err := msmG_prime_ds.MultiExp(Gs_prime, ds, common.MultiExpConf); err != nil {
		return Proof{}, fmt.Errorf("compute msm(G', d): %s", err)
	}
	if !msmG_prime_ds.Equal(&D) {
		return Proof{}, fmt.Errorf("msm(G', d) != D")
	}

	crsIPA := innerproductargument.CRS{
		Gs:       Gs,
		Gs_prime: Gs_prime,
		H:        crs.H,
	}

	ipaProof, err := innerproductargument.Prove(
		crsIPA,
		C,
		D,
		z,
		cs,
		ds,
		transcript,
		rand,
	)
	if err != nil {
		return Proof{}, fmt.Errorf("inner product proof: %s", err)
	}

	return Proof{
		C:        C,
		Rp:       r_p,
		IPAProof: ipaProof,
	}, nil
}

func Verify(
	proof Proof,
	crs CRS,
	Gsum bls12381.G1Affine,
	Hsum bls12381.G1Affine,
	B bls12381.G1Jac,
	result fr.Element,
	numBlinders int,
	transcript *transcript.Transcript,
	msmAccumulator *msmaccumulator.MsmAccumulator,
	rand *common.Rand,
) (bool, error) {
	// Step 1
	transcript.AppendPoints([]byte("gprod_step1"), &B)
	transcript.AppendScalars([]byte("gprod_step1"), result)
	alpha := transcript.GetAndAppendChallenge([]byte("gprod_alpha"))

	// Step 2
	transcript.AppendPoints([]byte("gprod_step2"), &proof.C)
	transcript.AppendScalars([]byte("gprod_step2"), proof.Rp)
	beta := transcript.GetAndAppendChallenge([]byte("gprod_beta"))
	if beta.IsZero() {
		return false, fmt.Errorf("beta is zero")
	}

	// Step 3
	var betaInv fr.Element
	betaInv.Inverse(&beta)
	us := make([]fr.Element, len(crs.Gs)+numBlinders)
	betaInvPow := betaInv
	for i := 0; i < len(crs.Gs); i++ {
		us[i] = betaInvPow
		betaInvPow.Mul(&betaInvPow, &betaInv)
	}
	for i := len(crs.Gs); i < len(us); i++ {
		us[i] = betaInvPow
	}
	var D, D_M, D_R bls12381.G1Affine
	D_M.ScalarMultiplication(&Gsum, common.FrToBigInt(&betaInv))
	D_R.ScalarMultiplication(&Hsum, common.FrToBigInt(&alpha))
	D.FromJacobian(&B).Sub(&D, &D_M).Add(&D, &D_R)

	// Step 4
	Gs := make([]bls12381.G1Affine, len(crs.Gs)+len(crs.Hs))
	copy(Gs, crs.Gs)
	copy(Gs[len(crs.Gs):], crs.Hs)

	var z, z_L, z_M fr.Element
	var betaExpL, betaExpLPlusOne fr.Element
	betaExpL.Exp(beta, big.NewInt(int64(len(crs.Gs))))
	betaExpLPlusOne.Mul(&betaExpL, &beta)
	z_L.Mul(&result, &betaExpL)
	z_M.Mul(&proof.Rp, &betaExpLPlusOne)
	z.Add(&z_L, &z_M)
	z.Add(&z, &minusOne)

	ipaCRS := innerproductargument.CRS{
		Gs: Gs,
		// TODO(jsign): not using Gs_prime, reconsider.
		H: crs.H,
	}

	var DAffine bls12381.G1Jac
	DAffine.FromAffine(&D) // TODO(jsign): despite doesn't require inversion, see if we can avoid this.
	ok, err := innerproductargument.Verify(
		&proof.IPAProof,
		&ipaCRS,
		proof.C,
		DAffine,
		z,
		us,
		transcript,
		msmAccumulator,
		rand,
	)
	if err != nil {
		return false, fmt.Errorf("inner product proof verification: %s", err)
	}

	return ok, nil
}
