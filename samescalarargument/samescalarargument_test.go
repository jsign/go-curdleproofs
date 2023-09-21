package samescalarargument

import (
	"fmt"
	"testing"
	"time"

	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/group"
	"github.com/jsign/curdleproofs/transcript"
	"github.com/stretchr/testify/require"
)

func TestProveVerify(t *testing.T) {
	t.Parallel()

	rand, err := common.NewRand(0)
	require.NoError(t, err)

	configs := []struct {
		name string

		group                 group.Group
		genRandomGroupElement func() (group.Element, error)
	}{
		{
			name:  "G1",
			group: &group.GroupG1{},
			genRandomGroupElement: func() (group.Element, error) {
				randG1Jac, err := rand.GetG1Jac()
				if err != nil {
					return nil, err
				}
				return group.FromG1Jac(randG1Jac), nil
			},
		},
		{
			name:  "Gt",
			group: &group.GroupGt{},
			genRandomGroupElement: func() (group.Element, error) {
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
			transcriptProver := transcript.New([]byte("same_scalar"))

			var crs CRS
			crs.Gt, err = config.genRandomGroupElement()
			require.NoError(t, err)
			crs.Gu, err = config.genRandomGroupElement()
			require.NoError(t, err)
			crs.H, err = config.genRandomGroupElement()
			require.NoError(t, err)

			R, err := config.genRandomGroupElement()
			require.NoError(t, err)
			S, err := config.genRandomGroupElement()
			require.NoError(t, err)

			k, err := rand.GetFrBigInt()
			require.NoError(t, err)
			r_t, err := rand.GetFrBigInt()
			require.NoError(t, err)
			r_u, err := rand.GetFrBigInt()
			require.NoError(t, err)

			tmp := config.group.CreateElement()
			T := group.NewGroupCommitment(config.group, crs.Gt, crs.H, tmp.ScalarMultiplication(R, &k), &r_t)
			U := group.NewGroupCommitment(config.group, crs.Gu, crs.H, tmp.ScalarMultiplication(S, &k), &r_u)

			now := time.Now()
			proof, err := Prove(
				config.group,
				crs,
				R,
				S,
				T,
				U,
				k,
				r_t,
				r_u,
				transcriptProver,
				rand,
			)
			require.NoError(t, err)
			fmt.Printf("Prove: %s\n", time.Since(now))

			t.Run("completeness", func(t *testing.T) {
				transcriptVerifier := transcript.New([]byte("same_scalar"))
				now := time.Now()
				require.True(t, Verify(
					config.group,
					proof,
					crs,
					R,
					S,
					T,
					U,
					transcriptVerifier,
				))
				fmt.Printf("Verify: %s\n", time.Since(now))
			})
		})
	}

	// TEMP: disabled for a while...
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
