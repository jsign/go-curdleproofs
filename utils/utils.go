package utils

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/group"
)

// TODO: moved from commons to avoid import cycle. try looking for a better separation.
func ShufflePermuteCommit(
	g group.Group,
	crsGs []group.Element,
	crsHs []group.Element,
	Rs []group.Element,
	Ss []group.Element,
	perm []uint32,
	k fr.Element,
	rand *common.Rand,
) ([]group.Element, []group.Element, group.Element, []fr.Element, error) {
	Ts := make([]group.Element, len(Rs))
	for i := range Ts {
		Ts[i] = g.CreateElement()
		Ts[i].ScalarMultiplication(Rs[i], k)
	}

	Us := make([]group.Element, len(Ss))
	for i := range Us {
		Us[i] = g.CreateElement()
		Us[i].ScalarMultiplication(Ss[i], k)
	}

	Ts = common.Permute(Ts, perm)
	Us = common.Permute(Us, perm)

	rangeFrs := make([]fr.Element, len(crsGs))
	for i := range perm {
		rangeFrs[i] = fr.NewElement(uint64(i))
	}

	permRangeFrs := common.Permute(rangeFrs, perm)
	M, M2 := g.CreateElement(), g.CreateElement()
	if _, err := M.MultiExp(crsGs, permRangeFrs); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("calculating M_1: %s", err)
	}
	rs_m, err := rand.GetFrs(common.N_BLINDERS)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("getting rs_m: %s", err)
	}
	if _, err := M2.MultiExp(crsHs, rs_m); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("calculating M_2: %s", err)
	}
	M.AddAssign(M2)

	return Ts, Us, M, rs_m, nil
}
