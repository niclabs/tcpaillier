package tcpaillier

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
)

var zero = big.NewInt(0)
var one = big.NewInt(1)
var two = big.NewInt(2)

// Paillier Threshold Scheme
type PubKey struct {
	N          *big.Int
	V          *big.Int
	Vi         []*big.Int
	L, K, S    uint8
	Delta      *big.Int
	Constant   *big.Int
	cached     *Cached
	RandSource io.Reader
}

type Cached struct {
	NPlusOne, NMinusOne, SPlusOne, NToS, NToSPlusOne, BigS *big.Int
}

func (pk *PubKey) Cache() *Cached {
	if pk.cached == nil {
		bigS := big.NewInt(int64(pk.S))
		nPlusOne := new(big.Int).Add(pk.N, one)
		nMinusOne := new(big.Int).Sub(pk.N, one)
		sPlusOne := new(big.Int).Add(bigS, one)
		nToS := new(big.Int).Exp(pk.N, bigS, nil)
		nToSPlusOne := new(big.Int).Exp(pk.N, sPlusOne, nil)
		pk.cached = &Cached{
			BigS:        bigS,
			NPlusOne:    nPlusOne,
			NMinusOne:   nMinusOne,
			NToS:        nToS,
			NToSPlusOne: nToSPlusOne,
		}
	}
	return pk.cached
}

func (pk *PubKey) Encrypt(msg []byte) (c *big.Int, err error) {
	m := new(big.Int).SetBytes(msg)
	cache := pk.Cache()
	nPlusOne := cache.NPlusOne
	nToS := cache.NToS
	nToSPlusOne := cache.NToSPlusOne
	nPlusOneToM := new(big.Int).Exp(nPlusOne, m, nToSPlusOne)
	r, err := pk.randomModNStar()
	rToNS := new(big.Int).Exp(r, nToS, nToSPlusOne)
	c = new(big.Int).Mul(nPlusOneToM, rToNS)
	c.Mod(c, nToSPlusOne)
	return
}

func (pk *PubKey) EncryptWithProof(message []byte) (c *big.Int, proof ZKProof, err error) {
	c, err = pk.Encrypt(message)
	if err != nil {
		return
	}
	proof, err = pk.encryptionProof(message, c)
	if err != nil {
		return
	}
	return
}

func (pk *PubKey) Add(cList ...*big.Int) (sum *big.Int, err error) {
	cache := pk.Cache()
	nToSPlusOne := cache.NToSPlusOne
	sum = big.NewInt(1)
	for i, ci := range cList {
		if ci.Cmp(nToSPlusOne) < 0 && ci.Cmp(zero) >= 0 {
			err = fmt.Errorf("c%d must be between 0 (inclusive) and N^(s+1) (exclusive)", i+1)
			return
		}
		sum.Mul(sum, ci)
		sum.Mod(sum, nToSPlusOne)
	}
	return
}

func (pk *PubKey) Multiply(c1 *big.Int, cons *big.Int) (mul *big.Int, err error) {
	cache := pk.Cache()
	nToSPlusOne := cache.NToSPlusOne
	mul = big.NewInt(1)
	if c1.Cmp(nToSPlusOne) < 0 && c1.Cmp(zero) >= 0 {
		err = fmt.Errorf("c1 must be between 0 (inclusive) and N^(s+1) (exclusive)")
		return
	}
	mul.Exp(c1, cons, nToSPlusOne)
	mul.Mod(mul, nToSPlusOne)
	return
}

func (pk *PubKey) MultiplyWithProof(c1 *big.Int, cons *big.Int) (mul *big.Int, proof ZKProof, err error) {

	mul, err = pk.Multiply(c1, cons)
	if err != nil {
		return
	}
	proof, err = pk.multiplicationProof(mul, cons)
	return
}

func (pk *PubKey) CombineShares(shares ...DecryptionShare) (dec []byte, err error) {
	if len(shares) < int(pk.K) {
		err = fmt.Errorf("needed %d shares to decrypt, but got %d", pk.K, len(shares))
		return
	}

	k := pk.K
	n := pk.N
	cache := pk.Cache()
	nToSPlusOne := cache.NToSPlusOne

	cPrime := new(big.Int).Set(one)

	indexes := make(map[uint8]int)

	for i, share := range shares {
		if j, ok := indexes[share.Ci.Index]; ok {
			err = fmt.Errorf("share %d repeated on indexes %d and %d", share.Index, i, j)
			return
		}
		indexes[share.Ci.Index] = i
	}

	for i := 0; i < int(k); i++ {
		lambda := pk.Delta
		for j := 0; j < int(k); j++ {
			if i != j {
				lambda.Mul(lambda, big.NewInt(-int64(shares[j].Ci.Index)))
				lambda.Div(lambda, big.NewInt(int64(shares[i].Ci.Index)-int64(shares[j].Ci.Index)))
			}
		}
		twoLambda := new(big.Int).Mul(lambda, two)
		ciToTwoLambda := new(big.Int).Exp(shares[i].Ci.Decryption, twoLambda, nToSPlusOne)
		cPrime.Mul(cPrime, ciToTwoLambda)
		cPrime.Mod(cPrime, nToSPlusOne)
	}
	L := new(big.Int).Sub(cPrime, one)
	L.Div(L, n)

	bigDec := new(big.Int).Mul(L, pk.Constant)
	bigDec.Mod(bigDec,n)
	dec = bigDec.Bytes()
	return
}

func (pk *PubKey) encryptionProof(message []byte, c *big.Int) (zk ZKProof, err error) {
	b := new(big.Int)
	w := new(big.Int)
	t := new(big.Int)
	z := new(big.Int)
	dummy := new(big.Int)

	nPlusOneToX := new(big.Int)
	uToN := new(big.Int)

	cache := pk.Cache()

	n := pk.N
	nPlusOne := cache.NPlusOne
	nToSPlusOne := cache.NToSPlusOne

	s, err := pk.randomModNStar()
	if err != nil {
		return
	}
	x, err := pk.randomModN()
	if err != nil {
		return
	}
	u, err := pk.randomModNPlusOneStar()
	if err != nil {
		return
	}

	nPlusOneToX.Exp(nPlusOne, x, nToSPlusOne)
	uToN.Exp(u, n, nToSPlusOne)
	b.Mul(nPlusOneToX, uToN).Mod(b, nToSPlusOne)

	sha256 := crypto.SHA256.New()
	sha256.Write(c.Bytes())
	sha256.Write(b.Bytes())
	e := sha256.Sum(nil)

	bigE := new(big.Int).SetBytes(e)
	bigAlpha := new(big.Int).SetBytes(message)

	eAlpha := new(big.Int).Mul(bigE, bigAlpha)

	dummy.Add(x, eAlpha)
	w.Mod(dummy, n)
	t.Div(dummy, n)

	sToE := new(big.Int).Exp(s, bigE, nil)
	uSToE := new(big.Int).Mul(u, sToE)
	nPlusOneToT := new(big.Int).Exp(nPlusOne, t, nil)
	z.Mul(uSToE, nPlusOneToT)

	zk = &EncryptZK{
		c: c,
		b: b,
		w: w,
		z: z,
	}
	return
}

func (pk *PubKey) multiplicationProof(ca *big.Int, alpha *big.Int) (zk ZKProof, err error) {
	cache := pk.Cache()
	nToSPlusOne := cache.NToSPlusOne
	nPlusOne := cache.NPlusOne
	n := pk.N
	if ca.Cmp(nToSPlusOne) < 0 && ca.Cmp(one) >= 0 {
		err = fmt.Errorf("c must be between 1 (inclusive) and N^(s+1) (exclusive)")
		return
	}

	s, err := pk.randomModNPlusOneStar()
	if err != nil {
		return
	}
	gamma, err := pk.randomModNPlusOneStar()
	if err != nil {
		return
	}

	nPlusOneToAlpha := new(big.Int).Exp(nPlusOne, alpha, nToSPlusOne)
	sToN := new(big.Int).Exp(s, n, nToSPlusOne)

	c := new(big.Int).Mul(nPlusOneToAlpha, sToN)
	c.Mod(c, nToSPlusOne)

	x, err := pk.randomModN()
	if err != nil {
		return
	}

	u, err := pk.randomModNPlusOneStar()
	if err != nil {
		return
	}

	v, err := pk.randomModNPlusOneStar()
	if err != nil {
		return
	}

	caToX := new(big.Int).Exp(ca, x, nToSPlusOne)
	vToN := new(big.Int).Exp(v, n, nToSPlusOne)
	a := new(big.Int).Mul(caToX, vToN)
	a.Mod(a, nToSPlusOne)

	nPlusOneToX := new(big.Int).Exp(nPlusOne, x, nToSPlusOne)
	uToN := new(big.Int).Exp(u, n, nToSPlusOne)
	b := new(big.Int).Mul(nPlusOneToX, uToN)
	b.Mod(b, nToSPlusOne)

	caToAlpha := new(big.Int).Exp(ca, alpha, nToSPlusOne)
	gammaToN := new(big.Int).Exp(gamma, n, nToSPlusOne)
	d := new(big.Int).Mul(caToAlpha, gammaToN)
	d.Mod(d, nToSPlusOne)

	sha256 := crypto.SHA256.New()
	sha256.Write(ca.Bytes())
	sha256.Write(c.Bytes())
	sha256.Write(d.Bytes())
	sha256.Write(a.Bytes())
	sha256.Write(b.Bytes())
	e := sha256.Sum(nil)

	bigE := new(big.Int).SetBytes(e)

	eAlpha := new(big.Int).Mul(bigE, alpha)

	dummy := new(big.Int).Add(x, eAlpha)
	w := new(big.Int).Mod(dummy, n)
	t := new(big.Int).Div(dummy, n)

	sToE := new(big.Int).Exp(s, bigE, nToSPlusOne)
	nPlusOneToT := new(big.Int).Exp(nPlusOne, t, nToSPlusOne)
	z := new(big.Int)
	z.Mul(u, sToE)
	z.Mul(z, nPlusOneToT)
	z.Mod(z, nToSPlusOne)

	caToT := new(big.Int).Exp(ca, t, nToSPlusOne)
	gammaToE := new(big.Int).Exp(gamma, bigE, nToSPlusOne)
	y := new(big.Int)
	y.Mul(v, caToT)
	y.Mul(y, gammaToE)
	y.Mod(y, nToSPlusOne)

	zk = &MulZK{
		c:  c,
		w:  w,
		d:  d,
		a:  a,
		b:  b,
		ca: ca,
		y:  y,
		z:  z,
	}
	return
}

func (pk *PubKey) randomModN() (r *big.Int, err error) {
	return rand.Int(pk.RandSource, pk.N)
}

func (pk *PubKey) randomModNStar() (r *big.Int, err error) {
	cache := pk.Cache()
	r, err = rand.Int(pk.RandSource, cache.NMinusOne)
	if err != nil {
		return
	}
	r.Add(r, one)
	return
}

func (pk *PubKey) randomModNPlusOneStar() (r *big.Int, err error) {
	r, err = pk.randomModN()
	if err != nil {
		return
	}
	r.Add(r, one)
	return
}
