package tcpaillier

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

// EncryptZK represents A ZKProof related to the encryption
// of A value.
type EncryptZK struct {
	B, W, Z *big.Int
}

// MulZK represents A ZKProof related to the multiplication
// of an encrypted value by A constant.
type MulZK struct {
	CAlpha, A, B, W, Y, Z *big.Int
}

// DecryptShareZK represents A ZKProof related to the decryption
// of an encrypted share by A constant.
type DecryptShareZK struct {
	V, Vi, Z, E *big.Int
}

// Verify verifies the Encryption ZKProof.
func (zk *EncryptZK) Verify(pk *PubKey, vals ...interface{}) error {

	if len(vals) != 1 {
		return fmt.Errorf("the extra value for verification should be only the encrypted value")
	}

	c, ok := vals[0].(*big.Int)
	if !ok {
		return fmt.Errorf("cannot cast first verification value as A *big.Int")
	}

	cache := pk.Cache()
	nPlusOne := cache.NPlusOne
	nToSPlusOne := cache.NToSPlusOne
	nToS := cache.NToS

	hash := sha256.New()
	hash.Write(c.Bytes())
	hash.Write(zk.B.Bytes())
	eHash := hash.Sum(nil)
	e := new(big.Int).SetBytes(eHash)

	// (n+1)^W % n^(s+1)
	nPlusOneToW := new(big.Int).Exp(nPlusOne, zk.W, nToSPlusOne)
	// Z^n % n^(s+1)
	zToN := new(big.Int).Exp(zk.Z, nToS, nToSPlusOne)
	// (n+1)^W*Z^n % n^(s+1)
	left := new(big.Int)
	left.Mul(nPlusOneToW, zToN).Mod(left, nToSPlusOne)

	// CAlpha^E % n^(s+1)
	cToE := new(big.Int).Exp(c, e, nToSPlusOne)
	// B*CAlpha^E % n^(s+1)
	right := new(big.Int)
	right.Mul(zk.B, cToE).Mod(right, nToSPlusOne)

	if left.Cmp(right) != 0 {
		return fmt.Errorf("zkproof failed")
	}
	return nil
}

// Verify verifies the Multiplication ZKProof.
func (zk *MulZK) Verify(pk *PubKey, vals ...interface{}) error {

	if len(vals) != 2 {
		return fmt.Errorf("the extra values for verification should be the result and the encrypted value")
	}

	d, ok := vals[0].(*big.Int)
	if !ok {
		return fmt.Errorf("cannot cast first verification value as A *big.Int")
	}

	ca, ok := vals[1].(*big.Int)
	if !ok {
		return fmt.Errorf("cannot cast first verification value as A *big.Int")
	}


	cache := pk.Cache()
	nPlusOne := cache.NPlusOne
	nToSPlusOne := cache.NToSPlusOne
	nToS := cache.NToS

	hash := sha256.New()
	hash.Write(ca.Bytes())
	hash.Write(zk.CAlpha.Bytes())
	hash.Write(d.Bytes())
	hash.Write(zk.A.Bytes())
	hash.Write(zk.B.Bytes())
	eBytes := hash.Sum(nil)

	e := new(big.Int).SetBytes(eBytes)

	// (n+1)^W % n^(s+1)
	nPlusOneToW := new(big.Int).Exp(nPlusOne, zk.W, nToSPlusOne)
	// Z^n % n^(s+1)
	zToNToS := new(big.Int).Exp(zk.Z, nToS, nToSPlusOne)
	// ((n+1)^W % n^(s+1)) * (Z^n % n^(s+1)) % n^(s+1)
	zk1 := new(big.Int)
	zk1.Mul(nPlusOneToW, zToNToS).Mod(zk1, nToSPlusOne)

	// CAlpha^E % n^(s+1)
	cToE := new(big.Int).Exp(zk.CAlpha, e, nToSPlusOne)
	// B * CAlpha^E % n^(s+1)
	zk2 := new(big.Int)
	zk2.Mul(cToE, zk.B).Mod(zk2, nToSPlusOne)

	if zk1.Cmp(zk2) != 0 {
		return fmt.Errorf("zkproof failed")
	}

	// ca^W % n^(s+1)
	caToW := new(big.Int).Exp(ca, zk.W, nToSPlusOne)
	// (Y^n % n^(s+1)
	yToNToS := new(big.Int).Exp(zk.Y, nToS, nToSPlusOne)
	// (ca^W % n^(s+1)) * (Y^n % n^(s+1)) % n^(s+1)
	zk3 := new(big.Int)
	zk3.Mul(caToW, yToNToS).Mod(zk3, nToSPlusOne)

	// d^E % n^(s+1)
	dToE := new(big.Int).Exp(d, e, nToSPlusOne)
	// A*d^E % n^(s+1)
	zk4 := new(big.Int).Mul(dToE, zk.A)
	zk4.Mod(zk4, nToSPlusOne)

	if zk3.Cmp(zk4) != 0 {
		return fmt.Errorf("zkproof failed")
	}
	return nil
}

// Verify verifies the ZKProof inside A DecryptionShare
func (zk *DecryptShareZK) Verify(pk *PubKey, vals ...interface{}) error {


	if len(vals) != 2 {
		return fmt.Errorf("the extra values for verification should be only the encrypted value and the decrypted share")
	}

	c, ok := vals[0].(*big.Int)
	if !ok {
		return fmt.Errorf("cannot cast first verification value as A *big.Int")
	}

	ds, ok := vals[1].(*DecryptionShare)
	if !ok {
		return fmt.Errorf("cannot cast second verification value as A decryptionShare")
	}

	cache := pk.Cache()
	nToSPlusOne := cache.NToSPlusOne
	cTo4 := new(big.Int).Exp(c, big.NewInt(4), nToSPlusOne)
	cTo4z := new(big.Int).Exp(cTo4, zk.Z, nToSPlusOne)
	ciTo2 := new(big.Int).Exp(ds.Ci, two, nToSPlusOne)
	minusE := new(big.Int).Neg(zk.E)
	minusTwoE := new(big.Int).Mul(minusE, two)
	ciToMinus2e := new(big.Int).Exp(ds.Ci, minusTwoE, nToSPlusOne)
	a := new(big.Int).Mul(cTo4z, ciToMinus2e)
	a.Mod(a, nToSPlusOne)

	vToZ := new(big.Int).Exp(zk.V, zk.Z, nToSPlusOne)
	viToMinusE := new(big.Int).Exp(zk.Vi, minusE, nToSPlusOne)
	b := new(big.Int).Mul(vToZ, viToMinusE)
	b.Mod(b, nToSPlusOne)

	hash := sha256.New()
	hash.Write(a.Bytes())
	hash.Write(b.Bytes())
	hash.Write(cTo4.Bytes())
	hash.Write(ciTo2.Bytes())
	eBytes := hash.Sum(nil)

	e := new(big.Int).SetBytes(eBytes)

	if e.Cmp(zk.E) != 0 {
		return fmt.Errorf("zkproof failed")
	}
	return nil
}
