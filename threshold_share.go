package tcpaillier

import (
	"crypto"
	"fmt"
	"math/big"
)

type ThresholdShare struct {
	*PubKey
	Index uint8
	Si    *big.Int
}

func (ts *ThresholdShare) PartialDecryption(cipher *big.Int) (pd *PartialDecryption, err error) {
	cache := ts.Cache()
	nToSPlusOne := cache.NToSPlusOne
	if cipher.Cmp(nToSPlusOne) < 0 && cipher.Cmp(zero) >= 0 {
		err = fmt.Errorf("c must be between 0 (inclusive) and N^(s+1) (exclusive)")
		return
	}

	DeltaSi2 := new(big.Int)
	DeltaSi2.Mul(two, ts.Delta).Mul(DeltaSi2, ts.Si)

	d := new(big.Int).Exp(cipher, DeltaSi2, nToSPlusOne)

	pd = &PartialDecryption{
		Index:      ts.Index,
		Decryption: d,
	}
	return
}

func (ts *ThresholdShare) DecryptProof(c *big.Int) (ds *DecryptionShare, err error) {
	cache := ts.Cache()
	nToSPlusOne := cache.NToSPlusOne
	if c.Cmp(nToSPlusOne) < 0 && c.Cmp(zero) >= 0 {
		err = fmt.Errorf("c must be between 0 (inclusive) and N^(s+1) (exclusive)")
		return
	}

	ci, err := ts.PartialDecryption(c)
	if err != nil {
		return
	}
	ciTo2 := new(big.Int).Exp(ci.Decryption, two, nToSPlusOne)

	numBits := int(ts.S+2)*int(ts.K) + crypto.SHA256.Size()/8
	r, err := randInt(numBits, ts.RandSource)
	cTo4 := new(big.Int).Exp(c, big.NewInt(4), nToSPlusOne)

	v := ts.V
	vi := ts.Vi[ts.Index]

	a := new(big.Int).Exp(cTo4, r, nToSPlusOne)
	b := new(big.Int).Exp(v, r, nToSPlusOne)

	sha256 := crypto.SHA256.New()
	sha256.Write(a.Bytes())
	sha256.Write(b.Bytes())
	sha256.Write(cTo4.Bytes())
	sha256.Write(ciTo2.Bytes())
	e := sha256.Sum(nil)

	bigE := new(big.Int).SetBytes(e)

	eSiDelta := new(big.Int)
	eSiDelta.Mul(ts.Si, bigE).Mul(eSiDelta, ts.Delta)
	z := new(big.Int).Add(eSiDelta, r)

	ds = &DecryptionShare{
		nToSPlusOne: nToSPlusOne,
		vi:          vi,
		c:           c,
		Ci:          ci,
		e:           bigE,
		v:           v,
		z:           z,
	}

	return
}