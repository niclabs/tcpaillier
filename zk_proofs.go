package tcpaillier

import (
	"crypto"
	"fmt"
	"math/big"
)

// ZKProof represents a Zero Knowledge Proof.
type ZKProof interface {
	// Verify returns nil if the verification of the ZKProof was successful,
	// and an error if it fails.
	Verify(pk *PubKey) error
}

// EncryptZK represents a ZKProof related to the encryption
// of a value.
type EncryptZK struct {
	c, b, w, z *big.Int
}

// MulZK represents a ZKProof related to the multiplication
// of an encrypted value by a constant.
type MulZK struct {
	ca, c, d, a, b, w, y, z, u *big.Int
}

func (zk *EncryptZK) Verify(pk *PubKey) error {

	cache := pk.Cache()
	nPlusOne := new(big.Int).Add(pk.N, one)
	nToSPlusOne := cache.NToSPlusOne
	n := pk.N

	sha256 := crypto.SHA256.New()
	sha256.Write(zk.c.Bytes())
	sha256.Write(zk.b.Bytes())
	e := sha256.Sum(nil)
	bigE := new(big.Int).SetBytes(e)

	nPlusOneToW := new(big.Int).Exp(nPlusOne, zk.w, nToSPlusOne)
	zToN := new(big.Int).Exp(zk.z, n, nToSPlusOne)

	left := new(big.Int).Mul(nPlusOneToW, zToN)
	left.Mod(left, nToSPlusOne)

	cToE := new(big.Int).Exp(zk.c, bigE, nToSPlusOne)
	right := new(big.Int).Mul(zk.b, cToE)
	right.Mod(right, nToSPlusOne)

	if left.Cmp(right) != 0 {
		return fmt.Errorf("verification failed")
	}
	return nil
}

func (zk *MulZK) Verify(pk *PubKey) error {

	cache := pk.Cache()
	nPlusOne := new(big.Int).Add(pk.N, one)
	nToSPlusOne := cache.NToSPlusOne
	n := pk.N

	sha256 := crypto.SHA256.New()
	sha256.Write(zk.ca.Bytes())
	sha256.Write(zk.c.Bytes())
	sha256.Write(zk.d.Bytes())
	sha256.Write(zk.a.Bytes())
	sha256.Write(zk.b.Bytes())
	e := sha256.Sum(nil)

	bigE := new(big.Int).SetBytes(e)

	nPlus1ToW := new(big.Int).Exp(nPlusOne, zk.w, nToSPlusOne)
	zToN := new(big.Int).Exp(zk.z, n, nToSPlusOne)
	zk1 := new(big.Int).Mul(nPlus1ToW, zToN)
	zk1.Mod(zk1, nToSPlusOne)

	cToE := new(big.Int).Exp(zk.c, bigE, nToSPlusOne)
	zk2 := new(big.Int).Mul(cToE, zk.u)
	zk2.Mod(zk2, nToSPlusOne)

	if zk1.Cmp(zk2) != 0 {
		return fmt.Errorf("zkproof failed")
	}

	caToW := new(big.Int).Exp(zk.ca, zk.w, nToSPlusOne)
	yToN := new(big.Int).Exp(zk.y, n, nToSPlusOne)
	zk3 := new(big.Int).Mul(caToW, yToN)
	zk3.Mod(zk3, nToSPlusOne)

	dToE := new(big.Int).Exp(zk.d, bigE, nToSPlusOne)
	zk4 := new(big.Int).Mul(dToE, zk.a)
	zk4.Mod(zk4, nToSPlusOne)

	if zk3.Cmp(zk4) != 0 {
		return fmt.Errorf("zkproof failed")
	}
	return nil
}
