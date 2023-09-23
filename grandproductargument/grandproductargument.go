package grandproductargument

import (
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/group"
	"github.com/jsign/curdleproofs/innerproductargument"
	"github.com/jsign/curdleproofs/transcript"
)

var minusOne fr.Element

func init() {
	one := fr.One()
	minusOne.Neg(&one)
}

type Proof struct {
	C        group.Element
	Rp       fr.Element
	IPAProof innerproductargument.Proof
}

type CRS struct {
	Gs []group.Element
	Hs []group.Element
	H  group.Element
}

var (
	labelGprodStep1 = []byte("gprod_step1")
	labelGprodStep2 = []byte("gprod_step2")
	labelGrpodAlpha = []byte("gprod_alpha")
	labelGprodBeta  = []byte("gprod_beta")
)

func Prove(
	g group.Group,

	crs CRS,
	B group.Element,
	result fr.Element,
	bs []fr.Element,
	r_bs []fr.Element,
	transcript *transcript.Transcript,
	rand *common.Rand,
) (Proof, error) {
	// Step 1.
	transcript.AppendGroupElements(labelGprodStep1, B)
	transcript.AppendScalars(labelGprodStep1, result)
	alpha := transcript.GetAndAppendChallenge(labelGrpodAlpha)

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
	C, C_L, C_R := g.CreateElement(), g.CreateElement(), g.CreateElement()
	if _, err := C_L.MultiExp(crs.Gs, cs); err != nil {
		return Proof{}, fmt.Errorf("compute C_L: %s", err)
	}
	if _, err := C_R.MultiExp(crs.Hs, r_cs); err != nil {
		return Proof{}, fmt.Errorf("compute C_R: %s", err)
	}
	C.Set(C_L).AddAssign(C_R)

	r_b_plus_alpha := make([]fr.Element, len(r_bs))
	for i := range r_b_plus_alpha {
		r_b_plus_alpha[i].Add(&r_bs[i], &alpha)
	}
	r_p, err := common.IPA(r_b_plus_alpha, r_cs)
	if err != nil {
		return Proof{}, fmt.Errorf("compute r_p: %s", err)
	}

	transcript.AppendGroupElements(labelGprodStep2, C)
	transcript.AppendScalars(labelGprodStep2, r_p)
	beta := transcript.GetAndAppendChallenge(labelGprodBeta)
	if beta.IsZero() {
		return Proof{}, fmt.Errorf("beta is zero")
	}
	// Step 3
	var betaInv fr.Element
	betaInv.Inverse(&beta)

	Gs_prime := make([]group.Element, len(crs.Gs))
	tmpBetaInv := betaInv
	for i := range Gs_prime {
		Gs_prime[i] = g.CreateElement()
		Gs_prime[i].ScalarMultiplication(crs.Gs[i], tmpBetaInv)
		tmpBetaInv.Mul(&tmpBetaInv, &betaInv)
	}
	Hs_prime := make([]group.Element, len(crs.Hs))
	for i := range Hs_prime {
		Hs_prime[i] = g.CreateElement()
		Hs_prime[i].ScalarMultiplication(crs.Hs[i], tmpBetaInv)
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
	D, D_L, D_R := g.CreateElement(), g.CreateElement(), g.CreateElement()
	if _, err := D_L.MultiExp(Gs_prime, betaPowers); err != nil {
		return Proof{}, fmt.Errorf("compute D_L: %s", err)
	}
	if _, err := D_R.MultiExp(Hs_prime, alphaBetaExpPlus1); err != nil {
		return Proof{}, fmt.Errorf("compute D_R: %s", err)
	}
	D.Set(B).SubAssign(D_L).AddAssign(D_R)

	// Step 4
	Gs := make([]group.Element, len(crs.Gs)+len(crs.Hs))
	for i := range crs.Gs {
		Gs[i] = g.CreateElement()
		Gs[i].Set(crs.Gs[i])
	}
	for i := range crs.Hs {
		Gs[len(crs.Gs)+i] = g.CreateElement()
		Gs[len(crs.Gs)+i].Set(crs.Hs[i])
	}
	Gs_prime = append(Gs_prime, Hs_prime...)

	var z, z_L, z_R fr.Element
	z_L.Mul(&r_p, &betaExpLPlus1)
	z_R.Mul(&result, &tmpBeta)
	z.Add(&z_L, &z_R)
	z.Add(&z, &minusOne)

	cs = append(cs, r_cs...)
	ds = append(ds, r_ds...)

	ipaC_D, err := common.IPA(cs, ds)
	if err != nil {
		return Proof{}, fmt.Errorf("compute IPA(C, D): %s", err)
	}

	if !ipaC_D.Equal(&z) {
		return Proof{}, fmt.Errorf("IPA(C, D) != z")
	}
	msmG_cs := g.CreateElement()
	if _, err := msmG_cs.MultiExp(Gs, cs); err != nil {
		return Proof{}, fmt.Errorf("compute msm(G, c): %s", err)
	}
	if !msmG_cs.Equal(C) {
		return Proof{}, fmt.Errorf("msm(G, c) != C")
	}
	msmG_prime_ds := g.CreateElement()
	if _, err := msmG_prime_ds.MultiExp(Gs_prime, ds); err != nil {
		return Proof{}, fmt.Errorf("compute msm(G', d): %s", err)
	}
	if !msmG_prime_ds.Equal(D) {
		return Proof{}, fmt.Errorf("msm(G', d) != D")
	}

	crsIPA := innerproductargument.CRS{
		Gs:       Gs,
		Gs_prime: Gs_prime,
		H:        crs.H,
	}

	ipaProof, err := innerproductargument.Prove(
		g,
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
	g group.Group,

	proof Proof,
	crs CRS,
	Gsum group.Element,
	Hsum group.Element,
	B group.Element,
	result fr.Element,
	numBlinders int,
	transcript *transcript.Transcript,
	msmAccumulator *group.MsmAccumulator,
	rand *common.Rand,
) (bool, error) {
	// Step 1
	transcript.AppendGroupElements(labelGprodStep1, B)
	transcript.AppendScalars(labelGprodStep1, result)
	alpha := transcript.GetAndAppendChallenge(labelGrpodAlpha)

	// Step 2
	transcript.AppendGroupElements(labelGprodStep2, proof.C)
	transcript.AppendScalars(labelGprodStep2, proof.Rp)
	beta := transcript.GetAndAppendChallenge(labelGprodBeta)
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
	D, D_M, D_R := g.CreateElement(), g.CreateElement(), g.CreateElement()
	D_M.ScalarMultiplication(Gsum, betaInv)
	D_R.ScalarMultiplication(Hsum, alpha)
	D.Set(B).Sub(D, D_M).Add(D, D_R)

	// Step 4
	Gs := make([]group.Element, len(crs.Gs)+len(crs.Hs))
	for i := range crs.Gs {
		Gs[i] = g.CreateElement()
		Gs[i] = crs.Gs[i]
	}
	for i := range crs.Hs {
		Gs[len(crs.Gs)+i] = g.CreateElement()
		Gs[len(crs.Gs)+i] = crs.Hs[i]
	}

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

	DAffine := g.CreateElement()
	DAffine.Set(D)
	ok, err := innerproductargument.Verify(
		g,
		proof.IPAProof,
		ipaCRS,
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

func (p *Proof) FromReader(r io.Reader) error {
	// d := bls12381.NewDecoder(r)
	// var tmp bls12381.G1Affine
	// if err := d.Decode(&tmp); err != nil {
	// 	return fmt.Errorf("decode C: %s", err)
	// }
	// p.C.FromAffine(&tmp)
	// if err := d.Decode(&p.Rp); err != nil {
	// 	return fmt.Errorf("decode Rp: %s", err)
	// }
	// if err := p.IPAProof.FromReader(r); err != nil {
	// 	return fmt.Errorf("decode IPAProof: %s", err)
	// }
	return nil
}

func (p *Proof) Serialize(w io.Writer) error {
	// var cAffine bls12381.G1Affine
	// cAffine.FromJacobian(&p.C)
	// e := bls12381.NewEncoder(w)
	// if err := e.Encode(&cAffine); err != nil {
	// 	return fmt.Errorf("encode C: %s", err)
	// }
	// if err := e.Encode(&p.Rp); err != nil {
	// 	return fmt.Errorf("encode Rp: %s", err)
	// }
	// if err := p.IPAProof.Serialize(w); err != nil {
	// 	return fmt.Errorf("encode IPAProof: %s", err)
	// }
	return nil
}
