package tcpaillier

import (
	"crypto"
	"crypto/rand"
	"io"
	"math/big"
)

var one = big.NewInt(1)

// Paillier Threshold Scheme with
type PubKey struct {
	N          *big.Int
	S          *big.Int
	V          *big.Int
	Vi         []*big.Int
	L, K       uint8
	Delta      *big.Int
	Constant   *big.Int
	cached     *Cached
	RandSource io.Reader
}

type Cached struct {
	NPlusOne, NMinusOne, SPlusOne, NToS, NToSPlusOne *big.Int
}

func (pk *PubKey) Cache() *Cached {
	if pk.cached == nil {
		nPlusOne := new(big.Int).Add(pk.N, one)
		nMinusOne := new(big.Int).Sub(pk.N, one)
		sPlusOne := new(big.Int).Add(pk.S, one)
		nToS := new(big.Int).Exp(pk.N, pk.S, nil)
		nToSPlusOne := new(big.Int).Exp(pk.N, sPlusOne, nil)
		pk.cached = &Cached{
			NPlusOne:    nPlusOne,
			NMinusOne:   nMinusOne,
			NToS:        nToS,
			NToSPlusOne: nToSPlusOne,
		}
	}
	return pk.cached
}

func (pk *PubKey) Encrypt(msg []byte, randSource io.Reader) (ciphered []byte, err error) {
	m := new(big.Int).SetBytes(msg)
	cache := pk.Cache()
	nPlusOne := cache.NPlusOne
	nToS := cache.NToS
	nToSPlusOne := cache.NToSPlusOne
	nPlusOneToM := new(big.Int).Exp(nPlusOne, m, nToSPlusOne)
	r, err := pk.randomModNStar()
	rToNS := new(big.Int).Exp(r, nToS, nToSPlusOne)
	c := new(big.Int).Mul(nPlusOneToM, rToNS)
	c.Mod(c, nToSPlusOne)
	ciphered = c.Bytes()
	return
}

func (pk *PubKey) EncryptWithProof(msg []byte, randSource io.Reader) (ciphered []byte, proof ZKProof, err error) {
	ciphered, err = pk.Encrypt(msg, randSource)
	if err != nil {
		return
	}
	proof, err = pk.proof(msg, ciphered)
	if err != nil {
		return
	}
	return
}

func (pk *PubKey) CombineShares(shares ...SigShare) []byte {
	return nil
}

func (pk *PubKey) proof(alpha []byte, ciphered []byte) (zk ZKProof, err error) {
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

	sha256.Write(ciphered)
	sha256.Write(b.Bytes())
	e := sha256.Sum(nil)
	bigE := new(big.Int).SetBytes(e)
	bigAlpha := new(big.Int).SetBytes(alpha)
	bigCiphered := new(big.Int).SetBytes(ciphered)

	eAlpha := new(big.Int).Mul(bigE, bigAlpha)

	dummy.Add(x, eAlpha)
	w.Mod(dummy, n)
	t.Div(dummy, n)

	sToE := new(big.Int).Exp(s, bigE, nil)
	uSToE := new(big.Int).Mul(u, sToE)
	nPlusOneToT := new(big.Int).Exp(nPlusOne, t, nil)
	z.Mul(uSToE, nPlusOneToT)

	zk = &EncryptZK{
		c:           bigCiphered,
		b:           b,
		w:           w,
		z:           z,
		n:           n,
		nToSPlusOne: nToSPlusOne,
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
