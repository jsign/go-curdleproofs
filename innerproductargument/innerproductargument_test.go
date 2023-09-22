package innerproductargument

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

func TestInnerProductArgument(t *testing.T) {
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
	for _, config := range configs {
		t.Run(config.name, func(t *testing.T) {

			var proof Proof
			{
				transcript := transcript.New([]byte("IPA"))
				crs, B, C, z, bs, cs, _ := setup(t, config, n)

				rand, err := common.NewRand(42)
				require.NoError(t, err)
				proof, err = Prove(
					config.group,
					crs,
					B,
					C,
					z,
					bs,
					cs,
					transcript,
					rand,
				)
				require.NoError(t, err)
			}

			t.Run("completeness", func(t *testing.T) {
				transcript := transcript.New([]byte("IPA"))
				msmAccumulator := group.NewMsmAccumulator(config.group)
				crs, B, C, z, _, _, us := setup(t, config, n)

				rand, err := common.NewRand(43)
				require.NoError(t, err)

				ok, err := Verify(
					config.group,
					proof,
					crs,
					B,
					C,
					z,
					us,
					transcript,
					msmAccumulator,
					rand,
				)
				require.NoError(t, err)
				require.True(t, ok)

				ok, err = msmAccumulator.Verify()
				require.NoError(t, err)
				require.True(t, ok)
			})
		})
	}

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
}

func setup(t *testing.T, config testConfig, n int) (CRS, group.Element, group.Element, fr.Element, []fr.Element, []fr.Element, []fr.Element) {
	rand, err := common.NewRand(0)
	require.NoError(t, err)

	crsGs := make([]group.Element, n)
	for i := range crsGs {
		crsGs[i], err = config.genRandomGroupElement(rand)
		require.NoError(t, err)
	}
	// There is actually a relationship between crs_G_vec and crs_G_prime_vec because of the grandproduct optimization
	// We generate a `vec_u` which has the discrete logs of every crs_G_prime element with respect to crs_G
	us, err := rand.GetFrs(n)
	require.NoError(t, err)
	crsGs_prime := make([]group.Element, n)
	for i := range crsGs_prime {
		crsGs_prime[i] = config.group.CreateElement()
	}
	for i := 0; i < n; i++ {
		crsGs_prime[i].ScalarMultiplication(crsGs[i], us[i])
	}
	H, err := config.genRandomGroupElement(rand)
	require.NoError(t, err)
	crs := CRS{
		Gs:       crsGs,
		Gs_prime: crsGs_prime,
		H:        H,
	}

	// Generate some random vectors
	bs, err := rand.GetFrs(n)
	require.NoError(t, err)
	cs, err := rand.GetFrs(n)
	require.NoError(t, err)

	z, err := common.IPA(bs, cs)
	require.NoError(t, err)

	// Create commitments
	B := config.group.CreateElement()
	_, err = B.MultiExp(crs.Gs, bs)
	require.NoError(t, err)
	C := config.group.CreateElement()
	_, err = C.MultiExp(crs.Gs_prime, cs)
	require.NoError(t, err)

	return crs, B, C, z, bs, cs, us
}
