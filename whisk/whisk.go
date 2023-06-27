package whisk

import (
	"bytes"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	curdleproof "github.com/jsign/curdleproofs"
	"github.com/jsign/curdleproofs/common"
)

func IsValidWhiskShuffleProof(
	crs CRS,
	preShuffleTrackers []WhiskTracker,
	postShuffleTrackers []WhiskTracker,
	m bls12381.G1Jac,
	shuffleProofBytes []byte,
	rand *common.Rand) (bool, error) {
	if len(preShuffleTrackers) != len(postShuffleTrackers) {
		return false, fmt.Errorf("pre and post shuffle trackers must be the same length")
	}

	var proof curdleproof.Proof
	if err := proof.FromReader(bytes.NewReader(shuffleProofBytes)); err != nil {
		return false, fmt.Errorf("failed to decode proof: %v", err)
	}
	Rs := make([]bls12381.G1Affine, len(preShuffleTrackers))
	Ss := make([]bls12381.G1Affine, len(preShuffleTrackers))
	Ts := make([]bls12381.G1Affine, len(postShuffleTrackers))
	Us := make([]bls12381.G1Affine, len(postShuffleTrackers))
	for i := 0; i < len(preShuffleTrackers); i++ {
		Rs[i], Ss[i] = preShuffleTrackers[i].getCoordinates()
		Ts[i], Us[i] = postShuffleTrackers[i].getCoordinates()
	}

	ok, err := curdleproof.Verify(
		proof,
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
		m,
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
		Rs[i], Ss[i] = preTrackers[i].getCoordinates()
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
		postTrackers[i] = WhiskTracker{
			R_G:  Rs[i],
			K_RG: Ss[i],
		}
	}

	return postTrackers, proofBytes, nil
}
