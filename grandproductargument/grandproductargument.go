package grandproductargument

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/innerproductargument"
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
	Gs []bls12381.G1Jac
	Hs []bls12381.G1Jac
	H  bls12381.G1Jac
}

func Prove(
	crs CRS,
	B bls12381.G1Jac,
	p fr.Element,
	bs []fr.Element,
	r_bs []fr.Element,
	transcript *transcript.Transcript,
	rand *common.Rand,
) (Proof, error) {
	// Step 1.
	transcript.AppendPoints([]byte("gprod_step1"), &B)
	transcript.AppendScalar([]byte("gprod_step1"), p)
	alpha := transcript.GetChallenge([]byte("gprod_alpha"))

	// Step 2.
	cs := make([]fr.Element, len(crs.Gs))
	cs[0] = fr.One()
	for i := 1; i < len(cs); i++ {
		cs[i].Mul(&cs[i-1], &bs[i])
	}
	r_cs, err := rand.GetFrs(len(r_bs))
	if err != nil {
		return Proof{}, fmt.Errorf("generate R_Cs: %s", err)
	}
	var C, C_L, C_R bls12381.G1Jac
	if _, err := C_L.MultiExp(bls12381.BatchJacobianToAffineG1(crs.Hs), cs, common.MultiExpConf); err != nil {
		return Proof{}, fmt.Errorf("compute C_L: %s", err)
	}
	if _, err := C_R.MultiExp(bls12381.BatchJacobianToAffineG1(crs.Hs), r_cs, common.MultiExpConf); err != nil {
		return Proof{}, fmt.Errorf("compute C_R: %s", err)
	}
	C.Set(&C_L).AddAssign(&C_R)

	r_b_plus_alpha := make([]fr.Element, len(r_bs)+1)
	copy(r_b_plus_alpha, r_bs)
	r_b_plus_alpha[len(r_bs)].Set(&alpha)
	r_p := common.IPA(r_b_plus_alpha, r_cs)
	transcript.AppendPoints([]byte("gprod_step2"), &C)
	transcript.AppendScalar([]byte("gprod_step2"), r_p)
	beta := transcript.GetChallenge([]byte("gprod_beta"))
	if beta.IsZero() {
		return Proof{}, fmt.Errorf("beta is zero")
	}
	// Step 3
	var betaInv fr.Element
	betaInv.Inverse(&beta)

	gs_prime := make([]bls12381.G1Jac, len(crs.Gs))
	tmpBetaInv := betaInv
	for i := range gs_prime {
		gs_prime[i].ScalarMultiplication(&crs.Gs[i], common.FrToBigInt(&tmpBetaInv))
		tmpBetaInv.Mul(&tmpBetaInv, &betaInv)
	}
	Hs_prime := make([]bls12381.G1Jac, len(crs.Hs))
	for i := range Hs_prime {
		Hs_prime[i].ScalarMultiplication(&crs.Hs[i], common.FrToBigInt(&tmpBetaInv))
	}
	bs_prime := make([]fr.Element, len(crs.Gs))
	tmpBeta := beta
	for i := range bs_prime {
		bs_prime[i].Mul(&bs[i], &tmpBeta)
		tmpBeta.Mul(&tmpBeta, &beta)
	}

	ds := make([]fr.Element, len(crs.Gs)+len(r_bs))
	tmpBeta = fr.One() // TODO(jsign): prob optimizable, since powers could be calculated in the previous step.
	betaPowers := make([]fr.Element, len(crs.Gs))
	for i := range bs_prime {
		ds[i].Sub(&bs_prime[i], &tmpBeta)
		betaPowers[i].Set(&tmpBeta)
		tmpBeta.Mul(&tmpBeta, &beta)
	}

	r_ds := make([]fr.Element, len(r_b_plus_alpha))
	var betaLPlus1 fr.Element
	betaLPlus1.Exp(beta, big.NewInt(int64(len(r_b_plus_alpha))))
	for i := range r_ds {
		r_ds[i].Mul(&betaLPlus1, &r_b_plus_alpha[i])
	}

	alphabetalplus1 := make([]fr.Element, len(r_bs))
	var D, D_L, D_R bls12381.G1Jac
	if _, err := D_R.MultiExp(bls12381.BatchJacobianToAffineG1(Hs_prime), alphabetalplus1, common.MultiExpConf); err != nil {
		return Proof{}, fmt.Errorf("compute D_R: %s", err)
	}
	if _, err := D_L.MultiExp(bls12381.BatchJacobianToAffineG1(gs_prime), betaPowers, common.MultiExpConf); err != nil {
		return Proof{}, fmt.Errorf("compute D_L: %s", err)
	}
	D.Set(&B).SubAssign(&D_L).AddAssign(&D_R)

	// Step 4
	Gs := make([]bls12381.G1Jac, len(crs.Gs)+len(crs.Hs))
	copy(Gs, crs.Gs)
	copy(Gs[len(crs.Gs):], crs.Hs)

	Gs_prime := append(gs_prime, Hs_prime...)

	var z, z_L, z_R fr.Element
	z_L.Mul(&p, &betaLPlus1)
	z_R.Mul(&r_p, &betaPowers[len(betaPowers)-1])
	z.Add(&z_L, &z_R)
	z.Add(&z, &minusOne)

	cs = append(cs, r_cs...)
	ds = append(ds, r_ds...)

	// Sanity checks
	ipaC_D := common.IPA(cs, ds)
	if !ipaC_D.Equal(&z) {
		return Proof{}, fmt.Errorf("IPA(C, D) != z")
	}
	var msmG_cs bls12381.G1Jac
	if _, err := msmG_cs.MultiExp(bls12381.BatchJacobianToAffineG1(Gs), cs, common.MultiExpConf); err != nil {
		return Proof{}, fmt.Errorf("compute msm(G, c): %s", err)
	}
	if !msmG_cs.Equal(&C) {
		return Proof{}, fmt.Errorf("msm(G, c) != C")
	}
	var msmG_prime_ds bls12381.G1Jac
	if _, err := msmG_prime_ds.MultiExp(bls12381.BatchJacobianToAffineG1(Gs_prime), ds, common.MultiExpConf); err != nil {
		return Proof{}, fmt.Errorf("compute msm(G', d): %s", err)
	}
	if !msmG_prime_ds.Equal(&D) {
		return Proof{}, fmt.Errorf("msm(G', d) != D")
	}

	crsIPA := innerproductargument.CRS{
		Gs:       bls12381.BatchJacobianToAffineG1(Gs),
		Gs_prime: bls12381.BatchJacobianToAffineG1(Gs_prime),
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
