package whisk

import (
	"bytes"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	curdleproof "github.com/jsign/curdleproofs"
	"github.com/jsign/curdleproofs/common"
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
