package samepermutationargument

import (
	"fmt"
	"testing"
	"time"

	mrand "math/rand"

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

func TestSamePermutationArgument(t *testing.T) {
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

			rand, err := common.NewRand(0)
			require.NoError(t, err)

			crs, A, M, as, perm, rs_a, rs_m := setup(t, config, n)
			start := time.Now()
			transcriptProver := transcript.New([]byte("sameperm"))
			proof, err := Prove(
				config.group,
				crs,
				A,
				M,
				as,
				perm,
				rs_a,
				rs_m,
				transcriptProver,
				rand,
			)
			require.NoError(t, err)
			fmt.Printf("Prove %s took %s\n", config.name, time.Since(start))

			t.Run("completeness", func(t *testing.T) {
				crs, A, M, as, _, _, _ := setup(t, config, n)
				transcriptVerifier := transcript.New([]byte("sameperm"))
				msmAccumulator := group.NewMsmAccumulator(config.group)

				Gsum := config.group.CreateElement()
				for _, g := range crs.Gs {
					Gsum.Add(Gsum, g)
				}
				Hsum := config.group.CreateElement()
				for _, h := range crs.Hs {
					Hsum.Add(Hsum, h)
				}

				start := time.Now()
				ok, err := Verify(
					config.group,
					proof,
					crs,
					Gsum,
					Hsum,
					A,
					M,
					as,
					common.N_BLINDERS,
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

func setup(t *testing.T, config testConfig, n int) (CRS, group.Element, group.Element, []fr.Element, []uint32, []fr.Element, []fr.Element) {
	rand, err := common.NewRand(0)
	require.NoError(t, err)

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

	rs_a, err := rand.GetFrs(common.N_BLINDERS)
	require.NoError(t, err)
	rs_m, err := rand.GetFrs(common.N_BLINDERS)
	require.NoError(t, err)

	perm := make([]uint32, n-common.N_BLINDERS)
	for i := range perm {
		perm[i] = uint32(i)
	}
	srand := mrand.New(mrand.NewSource(42))
	srand.Shuffle(len(perm), func(i, j int) { perm[i], perm[j] = perm[j], perm[i] })
	permFrs := make([]fr.Element, n-common.N_BLINDERS)
	for i := range perm {
		permFrs[i] = fr.NewElement(uint64(perm[i]))
	}

	as, err := rand.GetFrs(n - common.N_BLINDERS)
	require.NoError(t, err)
	permAs := common.Permute(as, perm)

	A, A_L, A_R := config.group.CreateElement(), config.group.CreateElement(), config.group.CreateElement()
	_, err = A_L.MultiExp(crsGs, permAs)
	require.NoError(t, err)
	_, err = A_R.MultiExp(crsHs, rs_a)
	require.NoError(t, err)
	A.Set(A_L).AddAssign(A_R)

	M, M_L, M_R := config.group.CreateElement(), config.group.CreateElement(), config.group.CreateElement()
	_, err = M_L.MultiExp(crsGs, permFrs)
	require.NoError(t, err)
	_, err = M_R.MultiExp(crsHs, rs_m)
	require.NoError(t, err)
	M.Set(M_L).AddAssign(M_R)

	return crs, A, M, as, perm, rs_a, rs_m
}
