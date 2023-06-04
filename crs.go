package curdleproof

import (
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/jsign/curdleproofs/common"
)

type CRS struct {
	Gs   []bls12381.G1Affine
	Hs   []bls12381.G1Affine
	H    bls12381.G1Jac
	Gt   bls12381.G1Jac
	Gu   bls12381.G1Jac
	Gsum bls12381.G1Affine
	Hsum bls12381.G1Affine
}

func GenerateCRS(size int, rand common.Rand) (CRS, error) {
	gs, err := rand.GetG1Affines(size)
	if err != nil {
		return CRS{}, fmt.Errorf("gen gs: %s", err)
	}
	hs, err := rand.GetG1Affines(size)
	if err != nil {
		return CRS{}, fmt.Errorf("gen hs: %s", err)
	}
	h, err := rand.GetG1Jac()
	if err != nil {
		return CRS{}, fmt.Errorf("gen h: %s", err)
	}
	gt, err := rand.GetG1Jac()
	if err != nil {
		return CRS{}, fmt.Errorf("gen gt: %s", err)
	}
	gu, err := rand.GetG1Jac()
	if err != nil {
		return CRS{}, fmt.Errorf("gen gu: %s", err)
	}
	var gsum bls12381.G1Affine
	for _, g := range gs {
		gsum.Add(&gsum, &g)
	}
	var hsum bls12381.G1Affine
	for _, h := range hs {
		hsum.Add(&hsum, &h)
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
