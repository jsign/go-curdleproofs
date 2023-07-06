package whisk

import (
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	curdleproof "github.com/jsign/curdleproofs"
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
	// Note: this part of the reference test isn't implemented since
	//       in this implementation the serialized proof is forced to
	//       be an array of length equal TRACKER_PROOF_SIZE.
}

func TestWhiskShuffleProof(t *testing.T) {
	rand, err := common.NewRand(0)
	require.NoError(t, err)

	crs, err := curdleproof.GenerateCRS(ELL, rand)
	require.NoError(t, err)

	shuffledTrackers := generateShuffleTrackers(t, rand)

	postTrackers, proofBytes, err := GenerateWhiskShuffleProof(crs, shuffledTrackers, rand)
	require.NoError(t, err)

	ok, err := IsValidWhiskShuffleProof(crs, shuffledTrackers, postTrackers, proofBytes, rand)
	require.NoError(t, err)
	require.True(t, ok)

	// Assert correct WHISK_SHUFFLE_PROOF_SIZE
	// Note: this part of the reference test isn't implemented since
	//       in this implementation the serialized proof is forced to
	//       be an array of length equal WHISK_SHUFFLE_PROOF_SIZE.
}

func TestWhiskFullLifecycle(t *testing.T) {
	rand, err := common.NewRand(0)
	require.NoError(t, err)
	crs, err := curdleproof.GenerateCRS(ELL, rand)
	require.NoError(t, err)

	// Initial tracker in state
	shuffledTrackers := generateShuffleTrackers(t, rand)

	proposerIndex := uint64(15400)
	proposerInitialK := fr.NewElement(proposerIndex)

	// Initial dummy values, r = 1
	state := State{
		proposerTracker:     computeTracker(proposerInitialK, fr.One()),
		proposerKCommitment: getKComm(proposerInitialK),
		shuffledTrackers:    shuffledTrackers,
	}

	// k must be kept
	proposerK, err := rand.GetFr()
	require.NoError(t, err)

	// On first proposal, validator creates tracker for registering
	block0 := produceBlock(t, crs, &state, proposerK, proposerIndex)
	// Block is valid
	processBlock(t, crs, &state, block0)

	// On second proposal, validator opens previously submited tracker
	block1 := produceBlock(t, crs, &state, proposerK, proposerIndex)
	// Block is valid
	processBlock(t, crs, &state, block1)
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

func generateShuffleTrackers(t *testing.T, rand *common.Rand) []WhiskTracker {
	wts := make([]WhiskTracker, ELL)
	for i := 0; i < ELL; i++ {
		k, err := rand.GetFr()
		require.NoError(t, err)
		wts[i] = generateTracker(t, rand, k)
	}
	return wts
}

// Construct the CRS
type Block struct {
	whiskOpeningProof        TrackerProofBytes
	whiskPostShuffleTrackers []WhiskTracker
	whiskShuffleProof        WhiskShuffleProofBytes
	whiskRegistrationProof   TrackerProofBytes
	whiskTracker             WhiskTracker
	whiskKCommitment         G1PointBytes
}

type State struct {
	proposerTracker     WhiskTracker
	proposerKCommitment G1PointBytes
	shuffledTrackers    []WhiskTracker
}

func processBlock(t *testing.T, crs curdleproof.CRS, state *State, block *Block) {
	rand, err := common.NewRand(0)
	require.NoError(t, err)

	// process_whisk_opening_proof
	ok, err := IsValidWhiskTrackerProof(state.proposerTracker, state.proposerKCommitment, block.whiskOpeningProof)
	require.NoError(t, err)
	require.True(t, ok)

	// whisk_process_shuffled_trackers
	ok, err = IsValidWhiskShuffleProof(crs, state.shuffledTrackers, block.whiskPostShuffleTrackers, block.whiskShuffleProof, rand)
	require.NoError(t, err)
	require.True(t, ok)

	// whisk_process_tracker_registration
	g1GenBytes := g1Gen.Bytes()
	if state.proposerTracker.rG == g1GenBytes {
		// First proposal
		ok, err := IsValidWhiskTrackerProof(block.whiskTracker, block.whiskKCommitment, block.whiskRegistrationProof)
		require.NoError(t, err)
		require.True(t, ok)
		state.proposerTracker = block.whiskTracker
		state.proposerKCommitment = block.whiskKCommitment
	}
	// `else` -> Next proposals, registration data not used
}

func produceBlock(t *testing.T, crs curdleproof.CRS, state *State, proposerK fr.Element, proposerIndex uint64) *Block {
	rand, err := common.NewRand(0)
	require.NoError(t, err)

	whiskPostShuffleTrackers, whiskShuffleProof, err := GenerateWhiskShuffleProof(crs, state.shuffledTrackers, rand)
	require.NoError(t, err)

	g1GenBytes := g1Gen.Bytes()
	isFirstProposal := state.proposerTracker.rG == g1GenBytes

	var whiskTracker WhiskTracker
	var whiskRegistrationProof TrackerProofBytes
	var whiskKCommitment G1PointBytes
	if isFirstProposal {
		// First proposal, validator creates tracker for registering
		whiskTracker = generateTracker(t, rand, proposerK)
		whiskKCommitment = getKComm(proposerK)
		whiskRegistrationProof, err = GenerateWhiskTrackerProof(whiskTracker, proposerK, rand)
		require.NoError(t, err)
	} else {
		// And subsequent proposals leave registration fields empty
		whiskTracker = computeTracker(fr.One(), fr.One())
		whiskKCommitment = getKComm(fr.One())
	}

	var kPrevProposal fr.Element
	if isFirstProposal {
		// On first proposal the k is computed deterministically and known to all
		kPrevProposal = fr.NewElement(proposerIndex)
	} else {
		// Subsequent proposals use same k for registered tracker
		kPrevProposal = proposerK
	}

	whiskOpeningProof, err := GenerateWhiskTrackerProof(state.proposerTracker, kPrevProposal, rand)
	require.NoError(t, err)

	return &Block{
		whiskOpeningProof,
		whiskPostShuffleTrackers,
		whiskShuffleProof,
		whiskRegistrationProof,
		whiskTracker,
		whiskKCommitment,
	}
}
