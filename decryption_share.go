package tcpaillier

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

// DecryptionShare represents a partial decryption of a value
// and the ZKProof of that decryption. It complies with ZKProof
// interface.
type DecryptionShare struct {
	Index          uint8
	c, v, vi, z, e *big.Int
	Ci             *big.Int
}

// Verify verifies the ZKProof inside a DecryptionShare
func (ds *DecryptionShare) Verify(pk *PubKey) error {
	cache := pk.Cache()
	nToSPlusOne := cache.NToSPlusOne
	cTo4 := new(big.Int).Exp(ds.c, big.NewInt(4), nToSPlusOne)
	cTo4z := new(big.Int).Exp(cTo4, ds.z, nToSPlusOne)
	ciTo2 := new(big.Int).Exp(ds.Ci, two, nToSPlusOne)
	minusE := new(big.Int).Neg(ds.e)
	minusTwoE := new(big.Int).Mul(minusE, two)
	ciToMinus2e := new(big.Int).Exp(ds.Ci, minusTwoE, nToSPlusOne)
	a := new(big.Int).Mul(cTo4z, ciToMinus2e)
	a.Mod(a, nToSPlusOne)

	vToZ := new(big.Int).Exp(ds.v, ds.z, nToSPlusOne)
	viToMinusE := new(big.Int).Exp(ds.vi, minusE, nToSPlusOne)
	b := new(big.Int).Mul(vToZ, viToMinusE)
	b.Mod(b, nToSPlusOne)

	hash := sha256.New()
	hash.Write(a.Bytes())
	hash.Write(b.Bytes())
	hash.Write(cTo4.Bytes())
	hash.Write(ciTo2.Bytes())
	eBytes := hash.Sum(nil)

	e := new(big.Int).SetBytes(eBytes)

	if e.Cmp(ds.e) != 0 {
		return fmt.Errorf("zkproof failed")
	}
	return nil
}
