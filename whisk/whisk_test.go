package whisk

import (
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
	"github.com/stretchr/testify/require"
)

func TestWhiskTrackerProof(t *testing.T) {
	t.Parallel()

	rand, err := common.NewRand(0)
	require.NoError(t, err)

	k, err := rand.GetFr()
	require.NoError(t, err)
	tracker := generateTracker(t, rand, k)
	kComm := getKComm(k)

	trackerProof, err := GenerateWhiskTrackerProof(tracker, k, rand)
	require.NoError(t, err)
	ok, err := IsValidWhiskTrackerProof(tracker, kComm, trackerProof)
	require.NoError(t, err)
	require.True(t, ok)

	// Assert correct TRACKER_PROOF_SIZE
	var trackerProof2 TrackerProof
	err = trackerProof2.FromBytes(trackerProof)
	require.NoError(t, err)
	require.Equal(t, TRACKER_PROOF_SIZE, len(trackerProof2.Serialize()))
}

func generateTracker(t *testing.T, rand *common.Rand, k fr.Element) WhiskTracker {
	r, err := rand.GetFr()
	require.NoError(t, err)
	return computeTracker(k, r)
}

func computeTracker(k, r fr.Element) WhiskTracker {
	var rG, krG bls12381.G1Affine
	rG.ScalarMultiplication(&g1Gen, common.FrToBigInt(&r))
	krG.ScalarMultiplication(&rG, common.FrToBigInt(&k))

	return WhiskTracker{rG: rG.Bytes(), krG: krG.Bytes()}
}

func getKComm(k fr.Element) G1PointBytes {
	var res bls12381.G1Affine
	return res.ScalarMultiplication(&g1Gen, common.FrToBigInt(&k)).Bytes()
}
