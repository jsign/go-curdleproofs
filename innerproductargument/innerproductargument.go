package innerproductargument

import (
	"fmt"
	"math/bits"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/msmaccumulator"
	"github.com/jsign/curdleproofs/transcript"
)

var (
	labelStep1 = []byte("ipa_step1")
	labelAlpha = []byte("ipa_alpha")
	labelBeta  = []byte("ipa_beta")
	labelLoop  = []byte("ipa_loop")
	labelGamma = []byte("ipa_gamma")
)

type CRS struct {
	Gs       []bls12381.G1Affine
	Gs_prime []bls12381.G1Affine
	H        bls12381.G1Jac
}

type Proof struct {
	B_c bls12381.G1Jac
	B_d bls12381.G1Jac

	L_Cs []bls12381.G1Jac
	R_Cs []bls12381.G1Jac
	L_Ds []bls12381.G1Jac
	R_Ds []bls12381.G1Jac

	c0 fr.Element
	d0 fr.Element
}

func Prove(
	crs CRS,
	C bls12381.G1Jac,
	D bls12381.G1Jac,
	z fr.Element,
	cs []fr.Element,
	ds []fr.Element,
	transcript *transcript.Transcript,
	rand *common.Rand,
) (Proof, error) {
	if len(cs) != len(ds) {
		return Proof{}, fmt.Errorf("cs and ds are not the same length")
	}
	if len(cs)&(len(cs)-1) != 0 {
		return Proof{}, fmt.Errorf("cs and ds are not a power of two")
	}

	// Step 1.
	rs_c, rs_d, err := generateIPABlinders(rand, cs, ds)
	if err != nil {
		return Proof{}, fmt.Errorf("generate IPA blinders: %s", err)
	}

	var B_c bls12381.G1Jac
	if _, err := B_c.MultiExp(crs.Gs, rs_c, common.MultiExpConf); err != nil {
		return Proof{}, fmt.Errorf("multiexp B_c: %s", err)
	}
	var B_d bls12381.G1Jac
	if _, err := B_d.MultiExp(crs.Gs_prime, rs_d, common.MultiExpConf); err != nil {
		return Proof{}, fmt.Errorf("multiexp B_d: %s", err)
	}

	transcript.AppendPoints(labelStep1, &C, &D)
	transcript.AppendScalars(labelStep1, z)
	transcript.AppendPoints(labelStep1, &B_c, &B_d)

	alpha := transcript.GetAndAppendChallenge(labelAlpha)
	beta := transcript.GetAndAppendChallenge(labelBeta)

	n := uint(len(cs))
	for i := 0; i < int(n); i++ {
		var tmp fr.Element
		tmp.Mul(&alpha, &cs[i])
		cs[i].Add(&rs_c[i], &tmp)
		tmp.Mul(&alpha, &ds[i])
		ds[i].Add(&rs_d[i], &tmp)
	}

	var H bls12381.G1Jac
	H.ScalarMultiplication(&crs.H, common.FrToBigInt(&beta))

	// Step 2.
	m := bits.Len(n) - 1
	L_Cs := make([]bls12381.G1Jac, 0, m)
	R_Cs := make([]bls12381.G1Jac, 0, m)
	L_Ds := make([]bls12381.G1Jac, 0, m)
	R_Ds := make([]bls12381.G1Jac, 0, m)

	for len(cs) > 1 {
		n /= 2

		c_L, c_R := common.SplitAt(cs, n)
		d_L, d_R := common.SplitAt(ds, n)
		G_L, G_R := common.SplitAt(crs.Gs, n)
		G_prime_L, G_prime_R := common.SplitAt(crs.Gs_prime, n)

		var L_C, L_C_L, L_C_R bls12381.G1Jac
		if _, err := L_C_L.MultiExp(G_R, c_L, common.MultiExpConf); err != nil {
			return Proof{}, fmt.Errorf("ipa L_C_1 multiexp: %s", err)
		}
		ipaCLDR, err := common.IPA(c_L, d_R)
		if err != nil {
			return Proof{}, fmt.Errorf("ipa L_C_2 multiexp: %s", err)
		}
		L_C_R.ScalarMultiplication(&H, common.FrToBigInt(&ipaCLDR))
		L_C.Set(&L_C_L)
		L_C.AddAssign(&L_C_R)

		var L_D bls12381.G1Jac
		if _, err := L_D.MultiExp(G_prime_L, d_R, common.MultiExpConf); err != nil {
			return Proof{}, fmt.Errorf("ipa L_D multiexp: %s", err)
		}

		var R_C, R_C_L, R_C_R bls12381.G1Jac
		if _, err := R_C_L.MultiExp(G_L, c_R, common.MultiExpConf); err != nil {
			return Proof{}, fmt.Errorf("ipa R_C_1 multiexp: %s", err)
		}
		ipaCRDL, err := common.IPA(c_R, d_L)
		if err != nil {
			return Proof{}, fmt.Errorf("ipa R_C_2 multiexp: %s", err)
		}
		R_C_R.ScalarMultiplication(&H, common.FrToBigInt(&ipaCRDL))
		R_C.Set(&R_C_L)
		R_C.AddAssign(&R_C_R)

		var R_D bls12381.G1Jac
		if _, err := R_D.MultiExp(G_prime_R, d_L, common.MultiExpConf); err != nil {
			return Proof{}, fmt.Errorf("ipa R_D multiexp: %s", err)
		}

		L_Cs = append(L_Cs, L_C)
		L_Ds = append(L_Ds, L_D)
		R_Cs = append(R_Cs, R_C)
		R_Ds = append(R_Ds, R_D)

		transcript.AppendPoints(labelLoop, &L_C, &L_D, &R_C, &R_D)
		gamma := transcript.GetAndAppendChallenge(labelGamma)
		if gamma.IsZero() {
			return Proof{}, fmt.Errorf("ipa gamma challenge is zero")
		}
		var gamma_inv fr.Element
		gamma_inv.Inverse(&gamma)

		for i := 0; i < int(n); i++ {
			var tmps fr.Element
			c_L[i].Add(&c_L[i], tmps.Mul(&gamma_inv, &c_R[i]))
			d_L[i].Add(&d_L[i], tmps.Mul(&gamma, &d_R[i]))

			var tmpp bls12381.G1Affine
			tmpp.ScalarMultiplication(&G_R[i], common.FrToBigInt(&gamma))
			G_L[i].Add(&G_L[i], &tmpp)

			tmpp.ScalarMultiplication(&G_prime_R[i], common.FrToBigInt(&gamma_inv))
			G_prime_L[i].Add(&G_prime_L[i], &tmpp)
		}

		cs = c_L
		ds = d_L
		crs.Gs = G_L
		crs.Gs_prime = G_prime_L
	}

	// TODO(jsign): sanity check that we end up with correct lengths (i.e: 1)

	return Proof{
		B_c:  B_c,
		B_d:  B_d,
		L_Cs: L_Cs,
		R_Cs: R_Cs,
		L_Ds: L_Ds,
		R_Ds: R_Ds,
		c0:   cs[0],
		d0:   ds[0],
	}, nil
}

func Verify(
	proof *Proof,
	crs *CRS,
	C bls12381.G1Jac,
	D bls12381.G1Jac,
	z fr.Element,
	us []fr.Element,
	transcript *transcript.Transcript,
	msmAccumulator *msmaccumulator.MsmAccumulator,
	rand *common.Rand,
) (bool, error) {
	// Step 1.
	transcript.AppendPoints(labelStep1, &C, &D)
	transcript.AppendScalars(labelStep1, z)
	transcript.AppendPoints(labelStep1, &proof.B_c, &proof.B_d)
	alpha := transcript.GetAndAppendChallenge(labelAlpha)
	beta := transcript.GetAndAppendChallenge(labelBeta)

	// Step 2.
	n := len(crs.Gs)
	if n&(n-1) != 0 {
		return false, fmt.Errorf("ipa n is not a power of two")
	}
	m := bits.Len(uint(n)) - 1

	gamma := make([]fr.Element, 0, m)
	for i := 0; i < m; i++ {
		transcript.AppendPoints(labelLoop, &proof.L_Cs[i], &proof.L_Ds[i], &proof.R_Cs[i], &proof.R_Ds[i])
		gamma = append(gamma, transcript.GetAndAppendChallenge(labelGamma))
	}
	gamma_inv := fr.BatchInvert(gamma)

	// Step 3.
	s := make([]fr.Element, n)
	s_prime := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		s[i] = fr.One()
		s_prime[i] = fr.One()
		for j := 0; j < m; j++ {
			if i&(1<<j) != 0 {
				s[i].Mul(&s[i], &gamma[m-j-1])
				s_prime[i].Mul(&s_prime[i], &gamma_inv[m-j-1])
			}
		}
	}

	// Accummulate check 1
	var AC1, AC1_L, AC1_M_1, AC1_M_2, AC1_M_3, AC1_R bls12381.G1Jac
	if _, err := AC1_L.MultiExp(bls12381.BatchJacobianToAffineG1(proof.L_Cs), gamma, common.MultiExpConf); err != nil {
		return false, fmt.Errorf("ipa AC1_L multiexp: %s", err)
	}
	AC1_M_1.Set(&proof.B_c)
	AC1_M_2.ScalarMultiplication(&C, common.FrToBigInt(&alpha))
	var alphasquaredtimesz fr.Element
	alphasquaredtimesz.Mul(&alpha, &alpha)
	alphasquaredtimesz.Mul(&alphasquaredtimesz, &z)
	var betaH bls12381.G1Jac
	betaH.ScalarMultiplication(&crs.H, common.FrToBigInt(&beta))
	AC1_M_3.ScalarMultiplication(&betaH, common.FrToBigInt(&alphasquaredtimesz))
	if _, err := AC1_R.MultiExp(bls12381.BatchJacobianToAffineG1(proof.R_Cs), gamma_inv, common.MultiExpConf); err != nil {
		return false, fmt.Errorf("ipa AC1_R multiexp: %s", err)
	}
	AC1.Set(&AC1_L)
	AC1.AddAssign(&AC1_M_1)
	AC1.AddAssign(&AC1_M_2)
	AC1.AddAssign(&AC1_M_3)
	AC1.AddAssign(&AC1_R)
	GplusH := make([]bls12381.G1Affine, len(crs.Gs)+1)
	copy(GplusH, crs.Gs)
	var HAffine bls12381.G1Affine
	HAffine.FromJacobian(&crs.H)
	GplusH[len(crs.Gs)].Set(&HAffine)
	for i := range s {
		s[i].Mul(&s[i], &proof.c0)
	}
	beta.Mul(&beta, &proof.d0)
	beta.Mul(&beta, &proof.c0)
	scalars := append(s, beta)

	if err := msmAccumulator.AccumulateCheck(AC1, scalars, GplusH, rand); err != nil {
		return false, fmt.Errorf("accumulate check 1: %s", err)
	}

	// Accummulate check 2
	var AC2, AC2_L, AC2_M_1, AC2_M_2, AC2_R bls12381.G1Jac
	if _, err := AC2_L.MultiExp(bls12381.BatchJacobianToAffineG1(proof.L_Ds), gamma, common.MultiExpConf); err != nil {
		return false, fmt.Errorf("multiexp: %s", err)
	}
	AC2_M_1.Set(&proof.B_d)
	AC2_M_2.ScalarMultiplication(&D, common.FrToBigInt(&alpha))
	if _, err := AC2_R.MultiExp(bls12381.BatchJacobianToAffineG1(proof.R_Ds), gamma_inv, common.MultiExpConf); err != nil {
		return false, fmt.Errorf("multiexp: %s", err)
	}
	AC2.Set(&AC2_L)
	AC2.AddAssign(&AC2_M_1)
	AC2.AddAssign(&AC2_M_2)
	AC2.AddAssign(&AC2_R)
	scalars = s_prime
	for i := range s_prime {
		scalars[i].Mul(&scalars[i], &us[i])
		scalars[i].Mul(&scalars[i], &proof.d0)
	}
	if err := msmAccumulator.AccumulateCheck(AC2, scalars, crs.Gs, rand); err != nil {
		return false, fmt.Errorf("accumulate check 1: %s", err)
	}

	return true, nil
}

func generateIPABlinders(rand *common.Rand, cs []fr.Element, ds []fr.Element) ([]fr.Element, []fr.Element, error) {
	n := len(cs)

	// Generate all the blinders but leave out two blinders from z
	rs, err := rand.GetFrs(n)
	if err != nil {
		return nil, nil, fmt.Errorf("generate rs: %s", err)
	}
	zs, err := rand.GetFrs(n - 2)
	if err != nil {
		return nil, nil, fmt.Errorf("generate zs: %s", err)
	}

	// We have to solve a system of two linear equations over the two unknowns: z_{n-1} and z_n (the two blinders we left out)
	// Consider first equation: <r, d> + <z, c> == 0
	// <=> r_1 * d_1 + ... + r_n * d_n + z_1 * c_1 + ... + z_{n-1} * c_{n-1} + z_n * c_n == 0
	// The last two products contain the unknowns whereas all the previous is a known quantity `omega` -- let's compute it below
	omegaL, err := common.IPA(rs, ds)
	if err != nil {
		return nil, nil, fmt.Errorf("compute omegaL: %s", err)
	}

	omegaR, err := common.IPA(zs[:n-2], cs[:n-2])
	if err != nil {
		return nil, nil, fmt.Errorf("compute omegaR: %s", err)
	}
	var omega fr.Element
	omega.Add(&omegaL, &omegaR)
	// Now let's consider the second equation: <r, z> == 0
	// <=> r_1 * z_1 + ... r_{n-1} * z_{n-1} * r_n * z_n == 0
	// Again, the last two products contain the unknowns whereas all the previous is a known quantity `delta` -- let's compute it below
	delta, err := common.IPA(rs[:n-2], zs[:n-2])
	if err != nil {
		return nil, nil, fmt.Errorf("compute delta: %s", err)
	}

	// Solving the first equation for z_{n-1} we get:
	//
	//   z_{n-1} = - c_{n-1}^-1 (z_n * c_n + omega)
	//
	// then plugging the above z_{n-1} into the second equation, we get:
	//
	//   z_n = (r_{n-1} * c_{n-1}^-1 * omega - delta) / (- r_{n-1} * c_{n-1}^-1 * c_n + r_{n-1})
	//
	// We compute these values below:

	var inv_c fr.Element
	inv_c.Inverse(&cs[n-2])

	var last_z, last_z_term1, last_z_term2 fr.Element
	last_z_term1.Mul(&rs[n-2], &inv_c)
	last_z_term1.Mul(&last_z_term1, &omega)
	last_z_term1.Sub(&last_z_term1, &delta)
	last_z_term2.Neg(&rs[n-2])
	last_z_term2.Mul(&last_z_term2, &inv_c)
	last_z_term2.Mul(&last_z_term2, &cs[n-1])
	last_z_term2.Add(&last_z_term2, &rs[n-1])
	if last_z_term2.IsZero() {
		return nil, nil, fmt.Errorf("last_z_term2 is zero")
	}
	last_z_term2.Inverse(&last_z_term2)
	last_z.Mul(&last_z_term1, &last_z_term2)

	var penultimate_z, penultimate_z_term1, penultimate_z_term2 fr.Element
	penultimate_z_term1.Neg(&inv_c)
	penultimate_z_term2.Mul(&last_z, &cs[n-1])
	penultimate_z_term2.Add(&penultimate_z_term2, &omega)
	penultimate_z.Mul(&penultimate_z_term1, &penultimate_z_term2)

	zs = append(zs, penultimate_z, last_z)

	// Make sure the constraints were satisfied
	checkTerm1, err := common.IPA(rs, ds)
	if err != nil {
		return nil, nil, fmt.Errorf("compute checkTerm1: %s", err)
	}
	checkTerm2, err := common.IPA(zs, cs)
	if err != nil {
		return nil, nil, fmt.Errorf("compute checkTerm2: %s", err)
	}
	if !checkTerm1.Add(&checkTerm1, &checkTerm2).IsZero() {
		return nil, nil, fmt.Errorf("failed to generate IPA blinders: constraints not satisfied")
	}
	check, err := common.IPA(rs, zs)
	if err != nil {
		return nil, nil, fmt.Errorf("compute check: %s", err)
	}
	if !check.IsZero() {
		return nil, nil, fmt.Errorf("failed to generate IPA blinders: constraints not satisfied")
	}

	return rs, zs, nil
}
