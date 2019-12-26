package tcpaillier

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// KeyShare represents a share of the private key
// used to decrypt values in paillier encryption scheme.
type KeyShare struct {
	*PubKey
	Index uint8
	Si    *big.Int
}

// PartialDecryption decrypts the encripted value partially, using only one
// keyShare.
func (ts *KeyShare) PartialDecryption(c *big.Int) (pd *big.Int, err error) {
	cache := ts.Cache()
	nToSPlusOne := cache.NToSPlusOne
	if c.Cmp(nToSPlusOne) >= 0 || c.Cmp(zero) < 0 {
		err = fmt.Errorf("cAlpha must be between 0 (inclusive) and N^(s+1) (exclusive)")
		return
	}

	DeltaSi2 := new(big.Int)
	DeltaSi2.Mul(two, ts.Delta).Mul(DeltaSi2, ts.Si)

	pd = new(big.Int).Exp(c, DeltaSi2, nToSPlusOne)
	return
}

// DecryptProof returns a DecryptionShare, that is composed by a ZKProof and
// a partially decrypted value.
func (ts *KeyShare) DecryptProof(c *big.Int) (ds *DecryptionShare, err error) {
	cache := ts.Cache()
	nToSPlusOne := cache.NToSPlusOne
	if c.Cmp(nToSPlusOne) >= 0 || c.Cmp(zero) < 0 {
		err = fmt.Errorf("cAlpha must be between 0 (inclusive) and N^(s+1) (exclusive)")
		return
	}

	numBits := int(ts.S+2)*int(ts.K) + crypto.SHA256.Size()*8
	r, err := RandomInt(numBits, ts.RandSource)
	cTo4 := new(big.Int).Exp(c, big.NewInt(4), nToSPlusOne)

	v := ts.V
	vi := ts.Vi[ts.Index-1]

	a := new(big.Int).Exp(cTo4, r, nToSPlusOne)
	b := new(big.Int).Exp(v, r, nToSPlusOne)

	ci, err := ts.PartialDecryption(c)
	if err != nil {
		return
	}
	ciTo2 := new(big.Int).Exp(ci, two, nToSPlusOne)


	hash := sha256.New()
	hash.Write(a.Bytes())
	hash.Write(b.Bytes())
	hash.Write(cTo4.Bytes())
	hash.Write(ciTo2.Bytes())
	eBytes := hash.Sum(nil)

	e := new(big.Int).SetBytes(eBytes)

	eSiDelta := new(big.Int)
	eSiDelta.Mul(ts.Si, e).Mul(eSiDelta, ts.Delta)
	z := new(big.Int).Add(eSiDelta, r)

	ds = &DecryptionShare{
		Index: ts.Index,
		vi:    vi,
		c:     c,
		Ci:    ci,
		e:     e,
		v:     v,
		z:     z,
	}

	return
}
