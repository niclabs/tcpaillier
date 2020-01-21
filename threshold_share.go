package tcpaillier

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// KeyShare represents A share of the private key
// used to decrypt values in paillier encryption scheme.
type KeyShare struct {
	*PubKey
	Index uint8
	Si    *big.Int
}

// PartialDecrypt decrypts the encrypted value partially, using only one
// keyShare.
func (ts *KeyShare) PartialDecrypt(c *big.Int) (ds *DecryptionShare, err error) {
	cache := ts.Cache()
	nToSPlusOne := cache.NToSPlusOne
	if c.Cmp(nToSPlusOne) >= 0 || c.Cmp(zero) < 0 {
		err = fmt.Errorf("CAlpha must be between 0 (inclusive) and N^(s+1) (exclusive)")
		return
	}

	DeltaSi2 := new(big.Int)
	DeltaSi2.Mul(two, ts.Delta).Mul(DeltaSi2, ts.Si)

	pd := new(big.Int).Exp(c, DeltaSi2, nToSPlusOne)

	ds = &DecryptionShare{
		Index: ts.Index,
		Ci:    pd,
	}

	return
}

// PartialDecryptWithProof returns A DecryptionShare, that is composed by A ZKProof and
// A partially decrypted value.
func (ts *KeyShare) PartialDecryptWithProof(c *big.Int) (ds *DecryptionShare, zk *DecryptShareZK, err error) {
	ds, err = ts.PartialDecrypt(c)
	if err != nil {
		return
	}
	zk, err = ts.PartialDecryptProof(c, ds)

	return
}

func (ts *KeyShare) PartialDecryptProof(c *big.Int, ds *DecryptionShare) (zk *DecryptShareZK, err error) {

	cache := ts.Cache()
	nToSPlusOne := cache.NToSPlusOne

	numBits := int(ts.S+2)*int(ts.K) + crypto.SHA256.Size()*8
	r, err := RandomInt(numBits)
	if err != nil {
		return
	}
	cTo4 := new(big.Int).Exp(c, big.NewInt(4), nToSPlusOne)
	v := ts.V
	vi := ts.Vi[ts.Index-1]

	a := new(big.Int).Exp(cTo4, r, nToSPlusOne)
	b := new(big.Int).Exp(v, r, nToSPlusOne)

	ciTo2 := new(big.Int).Exp(ds.Ci, two, nToSPlusOne)

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

	zk = &DecryptShareZK{
		Vi: vi,
		E:  e,
		V:  v,
		Z:  z,
	}
	return
}
