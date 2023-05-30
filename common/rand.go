package common

import (
	"encoding/binary"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"golang.org/x/crypto/sha3"
)

type Rand struct {
	rand        sha3.ShakeHash
	genG1Jac    bls12381.G1Jac
	genG1Affine bls12381.G1Affine
}

func NewRand(seed uint64) (*Rand, error) {
	var seedBytes [8]byte
	binary.BigEndian.PutUint64(seedBytes[:], seed)

	rand := sha3.NewShake256()
	if _, err := rand.Write(seedBytes[:]); err != nil {
		return nil, fmt.Errorf("writing seed: %s", err)
	}
	g1GenJac, _, g1GenAffine, _ := bls12381.Generators()
	return &Rand{
		rand:        rand,
		genG1Jac:    g1GenJac,
		genG1Affine: g1GenAffine,
	}, nil
}

func (r *Rand) GetFr() (fr.Element, error) {
	for {
		var byts [fr.Bytes]byte
		if _, err := r.rand.Read(byts[:]); err != nil {
			return fr.Element{}, fmt.Errorf("get randomness: %s", err)

		}
		var fe fr.Element
		if err := fe.SetBytesCanonical(byts[:]); err == nil {
			return fe, nil
		}
	}
}

func (r *Rand) GetG1Jac() (bls12381.G1Jac, error) {
	scalar, err := r.GetFr()
	if err != nil {
		return bls12381.G1Jac{}, fmt.Errorf("get random Fr: %s", err)
	}
	var scalarBigInt big.Int
	scalar.BigInt(&scalarBigInt)
	var res bls12381.G1Jac
	res.ScalarMultiplication(&r.genG1Jac, &scalarBigInt)

	return res, nil
}

func (r *Rand) GetG1Affine() (bls12381.G1Affine, error) {
	scalar, err := r.GetFr()
	if err != nil {
		return bls12381.G1Affine{}, fmt.Errorf("get random Fr: %s", err)
	}
	var scalarBigInt big.Int
	scalar.BigInt(&scalarBigInt)
	var res bls12381.G1Affine
	res.ScalarMultiplication(&r.genG1Affine, &scalarBigInt)

	return res, nil
}

func (r *Rand) GetG1Affines(n int) ([]bls12381.G1Affine, error) {
	var err error
	ret := make([]bls12381.G1Affine, n)
	for i := 0; i < n; i++ {
		ret[i], err = r.GetG1Affine()
		if err != nil {
			return nil, fmt.Errorf("get random G1Affine: %s", err)
		}
	}
	return ret, nil
}

func (r *Rand) GetFrs(n int) ([]fr.Element, error) {
	var err error
	ret := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		ret[i], err = r.GetFr()
		if err != nil {
			return nil, fmt.Errorf("get random Fr: %s", err)
		}
	}
	return ret, nil
}
