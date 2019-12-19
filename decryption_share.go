package tcpaillier

import (
	"crypto"
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

	fourZ := new(big.Int).Mul(ds.z, big.NewInt(4))
	cTo4 := new(big.Int).Exp(ds.c, fourZ, nToSPlusOne)
	ciTo2 := new(big.Int).Exp(ds.c, two, nToSPlusOne)
	minusE := new(big.Int).Neg(ds.e)
	minusTwoE := new(big.Int).Mul(minusE, two)
	ciToMinus2e := new(big.Int).Exp(ds.Ci, minusTwoE, nToSPlusOne)
	a := new(big.Int).Mul(cTo4, ciToMinus2e)

	vToZ := new(big.Int).Exp(ds.v, ds.z, nToSPlusOne)
	viToMinusE := new(big.Int).Exp(ds.vi, minusE, nToSPlusOne)
	b := new(big.Int).Mul(vToZ, viToMinusE)

	sha256 := crypto.SHA256.New()
	sha256.Write(a.Bytes())
	sha256.Write(b.Bytes())
	sha256.Write(cTo4.Bytes())
	sha256.Write(ciTo2.Bytes())
	e := sha256.Sum(nil)

	bigE := new(big.Int).SetBytes(e)

	if bigE.Cmp(ds.e) != 0 {
		return fmt.Errorf("zkproof failed")
	}
	return nil
}
