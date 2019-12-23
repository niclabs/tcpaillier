package tcpaillier

import (
	"crypto/sha256"
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
	ca, c, d, a, b, w, y, z *big.Int
}

// Verify verifies the Encryption ZKProof.
func (zk *EncryptZK) Verify(pk *PubKey) error {

	cache := pk.Cache()
	nPlusOne := cache.NPlusOne
	nToSPlusOne := cache.NToSPlusOne
	nToS := cache.NToS


	hash := sha256.New()
	hash.Write(zk.c.Bytes())
	hash.Write(zk.b.Bytes())
	eHash := hash.Sum(nil)
	e := new(big.Int).SetBytes(eHash)

	// (n+1)^w % n^(s+1)
	nPlusOneToW := new(big.Int).Exp(nPlusOne, zk.w, nToSPlusOne)
	// z^n % n^(s+1)
	zToN := new(big.Int).Exp(zk.z, nToS, nToSPlusOne)
	// (n+1)^w*z^n % n^(s+1)
	left := new(big.Int)
	left.Mul(nPlusOneToW, zToN).Mod(left, nToSPlusOne)

	// c^e % n^(s+1)
	cToE := new(big.Int).Exp(zk.c, e, nToSPlusOne)
	// b*c^e % n^(s+1)
	right := new(big.Int)
	right.Mul(zk.b, cToE).Mod(right, nToSPlusOne)

	if left.Cmp(right) != 0 {
		return fmt.Errorf("zkproof failed")
	}
	return nil
}

// Verify verifies the Multiplication ZKProof.
func (zk *MulZK) Verify(pk *PubKey) error {

	cache := pk.Cache()
	nPlusOne := cache.NPlusOne
	nToSPlusOne := cache.NToSPlusOne
	nToS := cache.NToS

	hash := sha256.New()
	hash.Write(zk.ca.Bytes())
	hash.Write(zk.c.Bytes())
	hash.Write(zk.d.Bytes())
	hash.Write(zk.a.Bytes())
	hash.Write(zk.b.Bytes())
	eBytes := hash.Sum(nil)

	e := new(big.Int).SetBytes(eBytes)

	// (n+1)^w % n^(s+1)
	nPlusOneToW := new(big.Int).Exp(nPlusOne, zk.w, nToSPlusOne)
	// z^n % n^(s+1)
	zToN := new(big.Int).Exp(zk.z, nToS, nToSPlusOne)
	// ((n+1)^w % n^(s+1)) * (z^n % n^(s+1)) % n^(s+1)
	zk1 := new(big.Int)
	zk1.Mul(nPlusOneToW, zToN).Mod(zk1, nToSPlusOne)

	// c^e % n^(s+1)
	cToE := new(big.Int).Exp(zk.c, e, nToSPlusOne)
	// b * c^e % n^(s+1)
	zk2 := new(big.Int)
	zk2.Mul(cToE, zk.b).Mod(zk2, nToSPlusOne)

	if zk1.Cmp(zk2) != 0 {
		return fmt.Errorf("zkproof failed")
	}

	// ca^w % n^(s+1)
	caToW := new(big.Int).Exp(zk.ca, zk.w, nToSPlusOne)
	// (y^n % n^(s+1)
	yToN := new(big.Int).Exp(zk.y, nToS, nToSPlusOne)
	// (ca^w % n^(s+1)) * (y^n % n^(s+1)) % n^(s+1)
	zk3 := new(big.Int)
	zk3.Mul(caToW, yToN).Mod(zk3, nToSPlusOne)

	// d^e % n^(s+1)
	dToE := new(big.Int).Exp(zk.d, e, nToSPlusOne)
	// a*d^e % n^(s+1)
	zk4 := new(big.Int).Mul(dToE, zk.a)
	zk4.Mod(zk4, nToSPlusOne)

	if zk3.Cmp(zk4) != 0 {
		return fmt.Errorf("zkproof failed")
	}
	return nil
}
