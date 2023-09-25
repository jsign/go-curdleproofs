package samemultiscalarargument

import (
	"fmt"
	"testing"
	"time"

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

func TestSameMultiscalarArgument(t *testing.T) {
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

			transcriptProver := transcript.New([]byte("same_msm"))
			rand, err := common.NewRand(42)
			require.NoError(t, err)

			crs_Gs, A, Z_t, Z_u, Ts, Us, xs := setup(t, config, n)

			start := time.Now()
			proof, err := Prove(
				config.group,
				crs_Gs,
				A,
				Z_t,
				Z_u,
				Ts,
				Us,
				xs,
				transcriptProver,
				rand,
			)
			require.NoError(t, err)
			fmt.Printf("Prove %s took %s\n", config.name, time.Since(start))

			t.Run("completeness", func(t *testing.T) {
				transcriptVerifier := transcript.New([]byte("same_msm"))
				rand, err := common.NewRand(43)
				require.NoError(t, err)

				start := time.Now()
				crs_Gs, A, Z_t, Z_u, Ts, Us, _ := setup(t, config, n)
				msmAccumulator := group.NewMsmAccumulator(config.group)

				ok, err := Verify(
					config.group,
					proof,
					crs_Gs,
					A,
					Z_t,
					Z_u,
					Ts,
					Us,
					transcriptVerifier,
					msmAccumulator,
					rand,
				)
				require.NoError(t, err)
				require.True(t, ok)

				startMsmVerif := time.Now()
				ok, err = msmAccumulator.Verify()
				require.NoError(t, err)
				require.True(t, ok)
				fmt.Printf("Verify %s took %s (%s+%s)\n", config.name, time.Since(start), startMsmVerif.Sub(start), time.Since(startMsmVerif))
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

func setup(t *testing.T, config testConfig, n int) ([]group.Element, group.Element, group.Element, group.Element, []group.Element, []group.Element, []fr.Element) {
	rand, err := common.NewRand(0)
	require.NoError(t, err)

	crs_Gs := make([]group.Element, n)
	for i := range crs_Gs {
		crs_Gs[i], err = config.genRandomGroupElement(rand)
		require.NoError(t, err)
	}
	Ts := make([]group.Element, n)
	for i := range Ts {
		Ts[i], err = config.genRandomGroupElement(rand)
		require.NoError(t, err)
	}
	Us := make([]group.Element, n)
	for i := range Us {
		Us[i], err = config.genRandomGroupElement(rand)
		require.NoError(t, err)
	}
	xs, err := rand.GetFrs(n)
	require.NoError(t, err)

	A, Z_t, Z_u := config.group.CreateElement(), config.group.CreateElement(), config.group.CreateElement()
	_, err = A.MultiExp(crs_Gs, xs)
	require.NoError(t, err)
	_, err = Z_t.MultiExp(Ts, xs)
	require.NoError(t, err)
	_, err = Z_u.MultiExp(Us, xs)
	require.NoError(t, err)

	return crs_Gs, A, Z_t, Z_u, Ts, Us, xs
}
