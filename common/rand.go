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
	rand  sha3.ShakeHash
	genG1 bls12381.G1Jac
}

func NewRand(seed uint64) (*Rand, error) {
	var seedBytes [8]byte
	binary.BigEndian.PutUint64(seedBytes[:], seed)

	rand := sha3.NewShake256()
	if _, err := rand.Write(seedBytes[:]); err != nil {
		return nil, fmt.Errorf("writing seed: %s", err)
	}
	g1Gen, _, _, _ := bls12381.Generators()
	return &Rand{
		rand:  rand,
		genG1: g1Gen,
	}, nil
}

func (cr *Rand) GetFr() (fr.Element, error) {
	for {
		var byts [fr.Bytes]byte
		if _, err := cr.rand.Read(byts[:]); err != nil {
			return fr.Element{}, fmt.Errorf("get randomness: %s", err)

		}
		var fe fr.Element
		if err := fe.SetBytesCanonical(byts[:]); err == nil {
			return fe, nil
		}
	}
}

func (cr *Rand) GetG1() (bls12381.G1Jac, error) {
	scalar, err := cr.GetFr()
	if err != nil {
		return bls12381.G1Jac{}, fmt.Errorf("get random Fr: %s", err)
	}
	var scalarBigInt big.Int
	scalar.BigInt(&scalarBigInt)
	var res bls12381.G1Jac
	res.ScalarMultiplication(&cr.genG1, &scalarBigInt)

	return res, nil
}
