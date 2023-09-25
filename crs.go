package curdleproof

import (
	"fmt"

	"github.com/jsign/curdleproofs/common"
	"github.com/jsign/curdleproofs/group"
)

type CRS struct {
	Gs   []group.Element
	Hs   []group.Element
	H    group.Element
	Gt   group.Element
	Gu   group.Element
	Gsum group.Element
	Hsum group.Element
}

// TODO: Clean up API if generic backend is used.
func GenerateCRS(size int, g group.Group, genRandGroupElement func() (group.Element, error)) (CRS, error) {
	var err error
	gs := make([]group.Element, size)
	for i := range gs {
		gs[i], err = genRandGroupElement()
		if err != nil {
			return CRS{}, fmt.Errorf("gen gs: %s", err)
		}
	}
	if err != nil {
		return CRS{}, fmt.Errorf("gen gs: %s", err)
	}
	hs := make([]group.Element, common.N_BLINDERS)
	for i := range hs {
		hs[i], err = genRandGroupElement()
		if err != nil {
			return CRS{}, fmt.Errorf("gen hs: %s", err)
		}
	}
	if err != nil {
		return CRS{}, fmt.Errorf("gen hs: %s", err)
	}
	h, err := genRandGroupElement()
	if err != nil {
		return CRS{}, fmt.Errorf("gen h: %s", err)
	}
	gt, err := genRandGroupElement()
	if err != nil {
		return CRS{}, fmt.Errorf("gen gt: %s", err)
	}
	gu, err := genRandGroupElement()
	if err != nil {
		return CRS{}, fmt.Errorf("gen gu: %s", err)
	}
	gsum := g.CreateElement()
	for _, g := range gs {
		gsum.Add(gsum, g)
	}
	hsum := g.CreateElement()
	for _, h := range hs {
		hsum.Add(hsum, h)
	}

	return CRS{
		Gs:   gs,
		Hs:   hs,
		H:    h,
		Gt:   gt,
		Gu:   gu,
		Gsum: gsum,
		Hsum: hsum,
	}, nil
}
