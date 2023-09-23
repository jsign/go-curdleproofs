package grandproductargument

import (
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/group"
	"github.com/jsign/curdleproofs/transcript"
	"github.com/stretchr/testify/require"
)

type testConfig struct {
	name                  string
	group                 group.Group
	genRandomGroupElement func(*common.Rand) (group.Element, error)
}

func TestCompletenessAndSoundess(t *testing.T) {
	t.Parallel()

	n := 128
	configs := []testConfig{
		{
			name:  "G1",
			group: &group.GroupG1{},
			genRandomGroupElement: func(rand *common.Rand) (group.Element, error) {
				randG1Aff, err := rand.GetG1Affine()
				if err != nil {
					return nil, err
				}
				var randG1Jac bls12381.G1Jac
				randG1Jac.FromAffine(&randG1Aff)
				return group.FromG1Jac(randG1Jac), nil
			},
		},
		{
			name:  "Gt",
			group: &group.GroupGt{},
			genRandomGroupElement: func(rand *common.Rand) (group.Element, error) {
				randGt, err := rand.GetGt()
				if err != nil {
					return nil, err
				}
				return group.FromGt(randGt), nil
			},
		},
	}

	rand, err := common.NewRand(0)
	require.NoError(t, err)

	for _, config := range configs {
		t.Run(config.name, func(t *testing.T) {

			var proof Proof
			{
				transcriptProver := transcript.New([]byte("gprod"))

				crsGs := make([]group.Element, n-common.N_BLINDERS)
				for i := range crsGs {
					crsGs[i], err = config.genRandomGroupElement(rand)
					require.NoError(t, err)
				}
				crsHs := make([]group.Element, common.N_BLINDERS)
				for i := range crsHs {
					crsHs[i], err = config.genRandomGroupElement(rand)
					require.NoError(t, err)
				}
				crsH, err := config.genRandomGroupElement(rand)
				require.NoError(t, err)
				crs := CRS{
					Gs: crsGs,
					Hs: crsHs,
					H:  crsH,
				}

				bs, err := rand.GetFrs(n - common.N_BLINDERS)
				require.NoError(t, err)
				r_bs, err := rand.GetFrs(common.N_BLINDERS)
				require.NoError(t, err)

				result := fr.One()
				for _, b := range bs {
					result.Mul(&result, &b)
				}

				B, B_L, B_R := config.group.CreateElement(), config.group.CreateElement(), config.group.CreateElement()
				_, err = B_L.MultiExp(crsGs, bs)
				require.NoError(t, err)
				_, err = B_R.MultiExp(crsHs, r_bs)
				require.NoError(t, err)
				B.AddAssign(B_L).AddAssign(B_R)

				proof, err = Prove(
					config.group,
					crs,
					B,
					result,
					bs,
					r_bs,
					transcriptProver,
					rand,
				)
				require.NoError(t, err)
			}

			t.Run("completeness", func(t *testing.T) {
				crs, Gsum, Hsum, B, result, transcriptVerifier, msmAccumulator := genVerifierParameters(t, config, n)
				ok, err := Verify(
					config.group,
					proof,
					crs,
					Gsum,
					Hsum,
					B,
					result,
					common.N_BLINDERS,
					transcriptVerifier,
					msmAccumulator,
					rand,
				)
				require.NoError(t, err)
				require.True(t, ok)

				ok, err = msmAccumulator.Verify()
				require.NoError(t, err)
				require.True(t, ok)
			})

			t.Run("soundness - wrong result", func(t *testing.T) {
				crs, Gsum, Hsum, B, result, transcriptVerifier, msmAccumulator := genVerifierParameters(t, config, n)
				one := fr.One()
				var resultPlusOne fr.Element
				resultPlusOne.Add(&result, &one)
				ok, err := Verify(
					config.group,
					proof,
					crs,
					Gsum,
					Hsum,
					B,
					resultPlusOne, // This is the reason why the verifier should not accept the proof.
					common.N_BLINDERS,
					transcriptVerifier,
					msmAccumulator,
					rand,
				)
				require.NoError(t, err)
				require.True(t, ok) // This is OK, because the ultimate check is in the MSM accumulator below.

				ok, err = msmAccumulator.Verify()
				require.NoError(t, err)
				require.False(t, ok) // Note we expect this to be false.
			})

			t.Run("soundness - wrong commitment to Bs", func(t *testing.T) {
				crs, Gsum, Hsum, B, result, transcriptVerifier, msmAccumulator := genVerifierParameters(t, config, n)
				randScalar, err := rand.GetFr()
				require.NoError(t, err)

				B.ScalarMultiplication(B, randScalar) // This is the reason why the verifier should not accept the proof.
				ok, err := Verify(
					config.group,
					proof,
					crs,
					Gsum,
					Hsum,
					B,
					result,
					common.N_BLINDERS,
					transcriptVerifier,
					msmAccumulator,
					rand,
				)
				require.NoError(t, err)
				require.True(t, ok) // This is OK, because the ultimate check is in the MSM accumulator below.

				ok, err = msmAccumulator.Verify()
				require.NoError(t, err)
				require.False(t, ok) // Note we expect this to be false.
			})

			// t.Run("encode/decode", func(t *testing.T) {
			// 	buf := bytes.NewBuffer(nil)
			// 	require.NoError(t, proof.Serialize(buf))
			// 	expected := buf.Bytes()

			// 	var proof2 Proof
			// 	require.NoError(t, proof2.FromReader(buf))

			// 	buf2 := bytes.NewBuffer(nil)
			// 	require.NoError(t, proof2.Serialize(buf2))

			// 	require.Equal(t, expected, buf2.Bytes())
			// })
		})
	}
}

// TOOD(jsign): replicat in other tests.
func genVerifierParameters(t *testing.T, config testConfig, n int) (CRS, group.Element, group.Element, group.Element, fr.Element, *transcript.Transcript, *group.MsmAccumulator) {
	rand, err := common.NewRand(0)
	require.NoError(t, err)

	transcriptVerifier := transcript.New([]byte("gprod"))
	msmAccumulator := group.NewMsmAccumulator(config.group)

	crsGs := make([]group.Element, n-common.N_BLINDERS)
	for i := range crsGs {
		crsGs[i], err = config.genRandomGroupElement(rand)
		require.NoError(t, err)
	}
	crsHs := make([]group.Element, common.N_BLINDERS)
	for i := range crsHs {
		crsHs[i], err = config.genRandomGroupElement(rand)
		require.NoError(t, err)
	}
	crsH, err := config.genRandomGroupElement(rand)
	require.NoError(t, err)
	Gsum := config.group.CreateElement()
	for _, g := range crsGs {
		Gsum.Add(Gsum, g)
	}
	Hsum := config.group.CreateElement()
	for _, h := range crsHs {
		Hsum.Add(Hsum, h)
	}
	crs := CRS{
		Gs: crsGs,
		Hs: crsHs,
		H:  crsH,
	}
	bs, err := rand.GetFrs(n - common.N_BLINDERS)
	require.NoError(t, err)
	r_bs, err := rand.GetFrs(common.N_BLINDERS)
	require.NoError(t, err)

	result := fr.One()
	for _, b := range bs {
		result.Mul(&result, &b)
	}

	B, B_L, B_R := config.group.CreateElement(), config.group.CreateElement(), config.group.CreateElement()
	_, err = B_L.MultiExp(crsGs, bs)
	require.NoError(t, err)
	_, err = B_R.MultiExp(crsHs, r_bs)
	require.NoError(t, err)
	B.AddAssign(B_L).AddAssign(B_R)

	return crs, Gsum, Hsum, B, result, transcriptVerifier, msmAccumulator
}
