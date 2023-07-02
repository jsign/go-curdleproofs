package whisk

import (
	"bytes"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	curdleproof "github.com/jsign/curdleproofs"
	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/transcript"
)

var (
	labelWhiskOpeningProof            = []byte("whisk_opening_proof")
	labelTrackerOpeningProof          = []byte("tracker_opening_proof")
	labelTrackerOpeningProofChallenge = []byte("tracker_opening_proof_challenge")
)

func IsValidWhiskShuffleProof(crs CRS, preST, postST []WhiskTracker, whiskShuffleProofBytes []byte, rand *common.Rand) (bool, error) {
	if len(preST) != len(postST) {
		return false, fmt.Errorf("pre and post shuffle trackers must be the same length")
	}

	var whiskProof WhiskShuffleProof
	if err := whiskProof.FromReader(bytes.NewReader(whiskShuffleProofBytes)); err != nil {
		return false, fmt.Errorf("decoding proof: %s", err)
	}

	var err error
	Rs := make([]bls12381.G1Affine, len(preST))
	Ss := make([]bls12381.G1Affine, len(preST))
	Ts := make([]bls12381.G1Affine, len(postST))
	Us := make([]bls12381.G1Affine, len(postST))
	for i := 0; i < len(preST); i++ {
		Rs[i], Ss[i], err = preST[i].getPoints()
		if err != nil {
			return false, fmt.Errorf("getting pre shuffle points: %s", err)
		}
		Ts[i], Us[i], err = postST[i].getPoints()
		if err != nil {
			return false, fmt.Errorf("getting post shuffle points: %s", err)
		}
	}

	ok, err := curdleproof.Verify(
		whiskProof.Proof,
		curdleproof.CRS{
			Gs:   crs.Gs,
			Hs:   crs.Hs,
			H:    crs.H,
			Gt:   crs.Gt,
			Gu:   crs.Gu,
			Gsum: crs.Gsum,
			Hsum: crs.Hsum,
		},
		Rs,
		Ss,
		Ts,
		Us,
		whiskProof.M,
		rand,
	)
	if err != nil {
		return false, fmt.Errorf("verifying proof: %s", err)
	}

	return ok, nil
}

func GenerateWhiskShuffleProof(crs CRS, preTrackers []WhiskTracker, rand *common.Rand) ([]WhiskTracker, []byte, error) {
	permutation, err := rand.GeneratePermutation(ELL)
	if err != nil {
		return nil, nil, fmt.Errorf("generating permutation: %s", err)
	}
	k, err := rand.GetFr()
	if err != nil {
		return nil, nil, fmt.Errorf("generating k: %s", err)
	}

	Rs := make([]bls12381.G1Affine, len(preTrackers))
	Ss := make([]bls12381.G1Affine, len(preTrackers))
	for i := 0; i < len(preTrackers); i++ {
		Rs[i], Ss[i], err = preTrackers[i].getPoints()
		if err != nil {
			return nil, nil, fmt.Errorf("getting points: %s", err)
		}
	}

	Ts, Us, M, rs_m, err := common.ShufflePermuteCommit(crs.Gs, crs.Hs, Rs, Ss, permutation, k, rand)
	if err != nil {
		return nil, nil, fmt.Errorf("shuffling and permuting: %s", err)
	}

	proof, err := curdleproof.Prove(
		curdleproof.CRS{
			Gs:   crs.Gs,
			Hs:   crs.Hs,
			H:    crs.H,
			Gt:   crs.Gt,
			Gu:   crs.Gu,
			Gsum: crs.Gsum,
			Hsum: crs.Hsum,
		},
		Rs,
		Ss,
		Ts,
		Us,
		M,
		permutation,
		k,
		rs_m,
		rand)
	if err != nil {
		return nil, nil, fmt.Errorf("generating proof: %s", err)
	}

	whiskProof := WhiskShuffleProof{M: M, Proof: proof}
	proofBytes, err := whiskProof.Serialize()
	if err != nil {
		return nil, nil, fmt.Errorf("serializing proof: %s", err)
	}

	postTrackers := make([]WhiskTracker, len(preTrackers))
	for i := 0; i < len(preTrackers); i++ {
		postTrackers[i] = NewWhiskTracker(Rs[i], Ss[i])
	}

	return postTrackers, proofBytes, nil
}

func IsValidWhiskTrackerProof(tracker WhiskTracker, kComm G1PointBytes, trackerProofBytes TrackerProofBytes) (bool, error) {
	var trackerProof TrackerProof
	if err := trackerProof.FromBytes(trackerProofBytes); err != nil {
		return false, fmt.Errorf("decoding proof: %s", err)
	}

	rG, krG, err := tracker.getPoints()
	if err != nil {
		return false, fmt.Errorf("deserializing rG and krG: %s", err)
	}
	var kG bls12381.G1Affine
	if err := kG.X.SetBytesCanonical(kComm[:]); err != nil {
		return false, fmt.Errorf("deserializing kG: %s", err)
	}

	transcript := transcript.New(labelWhiskOpeningProof)
	transcript.AppendPointsAffine(labelTrackerOpeningProof, []bls12381.G1Affine{kG, g1Gen, krG, rG, trackerProof.A, trackerProof.B}...)

	challenge := transcript.GetAndAppendChallenge(labelTrackerOpeningProofChallenge)

	var A_prime, A_prime_R bls12381.G1Affine
	A_prime_R.ScalarMultiplication(&kG, common.FrToBigInt(&challenge))
	A_prime.ScalarMultiplication(&g1Gen, common.FrToBigInt(&trackerProof.S))
	A_prime.Add(&A_prime, &A_prime_R)

	var B_prime_R, B_prime bls12381.G1Affine
	B_prime_R.ScalarMultiplication(&krG, common.FrToBigInt(&challenge))
	B_prime_R.ScalarMultiplication(&rG, common.FrToBigInt(&trackerProof.S))
	B_prime.Add(&B_prime, &B_prime_R)

	return A_prime.Equal(&trackerProof.A) && B_prime.Equal(&trackerProof.B), nil
}

func GenerateWhiskTrackerProof(tracker WhiskTracker, k fr.Element, rand common.Rand) (TrackerProofBytes, error) {
	rG, krG, err := tracker.getPoints()
	if err != nil {
		return TrackerProofBytes{}, fmt.Errorf("deserializing rG and krG: %s", err)
	}

	var kG bls12381.G1Affine
	kG.ScalarMultiplication(&g1Gen, common.FrToBigInt(&k))
	blinder, err := rand.GetFr()
	if err != nil {
		return TrackerProofBytes{}, fmt.Errorf("generating blinder: %s", err)
	}
	var A, B bls12381.G1Affine
	A.ScalarMultiplication(&g1Gen, common.FrToBigInt(&blinder))
	B.ScalarMultiplication(&rG, common.FrToBigInt(&blinder))

	transcript := transcript.New(labelWhiskOpeningProof)
	transcript.AppendPointsAffine(
		labelTrackerOpeningProof, []bls12381.G1Affine{kG, g1Gen, krG, rG, A, B}...)

	challenge := transcript.GetAndAppendChallenge(labelTrackerOpeningProofChallenge)

	var s, tmp fr.Element
	s.Add(&blinder, tmp.Mul(&challenge, &k))

	trackerProof := TrackerProof{A: A, B: B, S: s}

	return trackerProof.Serialize()
}
