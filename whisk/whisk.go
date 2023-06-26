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
	rs := make([]bls12381.G1Affine, len(preShuffleTrackers))
	ss := make([]bls12381.G1Affine, len(preShuffleTrackers))
	ts := make([]bls12381.G1Affine, len(postShuffleTrackers))
	us := make([]bls12381.G1Affine, len(postShuffleTrackers))
	for i := 0; i < len(preShuffleTrackers); i++ {
		rs[i], ss[i] = preShuffleTrackers[i].getCoordinates()
		ts[i], us[i] = postShuffleTrackers[i].getCoordinates()
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
		rs,
		ss,
		ts,
		us,
		m,
		rand,
	)
	if err != nil {
		return false, fmt.Errorf("verifying proof: %s", err)
	}

	return ok, nil
}
