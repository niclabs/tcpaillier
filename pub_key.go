package tcpaillier

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
)

var zero = big.NewInt(0)
var one = big.NewInt(1)
var two = big.NewInt(2)

// PubKey represents a Paillier Public Key and its metainformation. It contains a
// cached field, with precomputed values.
// It also is linked with a random source, used by  the processes that require it.
type PubKey struct {
	N          *big.Int
	V          *big.Int
	Vi         []*big.Int
	L, K, S    uint8
	Delta      *big.Int
	Constant   *big.Int
	RandSource io.Reader
	cached     *cached
}

// cached contains the cached PubKey values.
type cached struct {
	NPlusOne, NMinusOne, SPlusOne, NToS, NToSPlusOne, BigS *big.Int
}

// Cache initializes the cached values and returns the structure.
func (pk *PubKey) Cache() *cached {
	if pk.cached == nil {
		// S
		bigS := big.NewInt(int64(pk.S))
		// n+1
		nPlusOne := new(big.Int).Add(pk.N, one)
		// n-1
		nMinusOne := new(big.Int).Sub(pk.N, one)
		// (s+1)
		sPlusOne := new(big.Int).Add(bigS, one)
		// n^s
		nToS := new(big.Int).Exp(pk.N, bigS, nil)
		// n^(s+1)
		nToSPlusOne := new(big.Int).Exp(pk.N, sPlusOne, nil)
		pk.cached = &cached{
			BigS:        bigS,
			SPlusOne:    sPlusOne,
			NPlusOne:    nPlusOne,
			NMinusOne:   nMinusOne,
			NToS:        nToS,
			NToSPlusOne: nToSPlusOne,
		}
	}
	return pk.cached
}

// Encrypt encrypts a message and returns its encryption as a big Integer c.
// If there is an error, it returns a nil integer as c.
func (pk *PubKey) Encrypt(msg []byte) (c *big.Int, err error) {
	m := new(big.Int).SetBytes(msg)
	cache := pk.Cache()
	// n+1
	nPlusOne := cache.NPlusOne
	// n^s
	nToS := cache.NToS
	// n^(s+1)
	nToSPlusOne := cache.NToSPlusOne
	// (n+1)^m % n^(s+1)
	nPlusOneToM := new(big.Int).Exp(nPlusOne, m, nToSPlusOne)
	r, err := pk.randomModNStar()
	// r^(n^s) % n^(s+1)
	rToNToS := new(big.Int).Exp(r, nToS, nToSPlusOne)
	// (n+1)^m * t^(n^s) % n^(s+1)
	c = new(big.Int).Mul(nPlusOneToM, rToNToS)
	c.Mod(c, nToSPlusOne)
	return
}

// EncryptWithProof encrypts a message and returns its encryption as a big Integer c.
// It also returns a ZKProof that demonstrates that the encrypted value corresponds to the
// message. If there is an error, it returns a nil integer as c.
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

// Add adds an indeterminate number of encrypted values and returns its encrypted sum, or an error
// if the value cannot be determined.
func (pk *PubKey) Add(cList ...*big.Int) (sum *big.Int, err error) {
	cache := pk.Cache()
	nToSPlusOne := cache.NToSPlusOne
	sum = big.NewInt(1)
	for i, ci := range cList {
		if ci.Cmp(nToSPlusOne) >= 0 || ci.Cmp(zero) < 0 {
			err = fmt.Errorf("c%d must be between 0 (inclusive) and N^(s+1) (exclusive)", i+1)
			return
		}
		sum.Mul(sum, ci)
		sum.Mod(sum, nToSPlusOne)
	}
	return
}

// Multiply multiplies a encrypted value by a constant. It returns an error if it is not able to
// multiply the value.
func (pk *PubKey) Multiply(c1 *big.Int, cons *big.Int) (mul *big.Int, err error) {
	cache := pk.Cache()
	nToSPlusOne := cache.NToSPlusOne
	mul = big.NewInt(1)
	if c1.Cmp(nToSPlusOne) >= 0 || c1.Cmp(zero) < 0 {
		err = fmt.Errorf("c1 must be between 0 (inclusive) and N^(s+1) (exclusive)")
		return
	}
	mul.Exp(c1, cons, nToSPlusOne)
	mul.Mod(mul, nToSPlusOne)
	return
}

// MultiplyWithProof multiplies an encrypted value by a constant and returns it with a ZKProof of the
// multiplication. It returns an error if it is not able to multiply the value.
func (pk *PubKey) MultiplyWithProof(c1 *big.Int, cons *big.Int) (mul *big.Int, proof ZKProof, err error) {

	mul, err = pk.Multiply(c1, cons)
	if err != nil {
		return
	}
	proof, err = pk.multiplicationProof(mul, cons)
	return
}

// CombineShares joins partial decryptions of a value and returns a decrypted value.
// It checks that the number of values is equal or more than the threshold.
func (pk *PubKey) CombineShares(shares ...*DecryptionShare) (dec []byte, err error) {
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
		if j, ok := indexes[share.Index]; ok {
			err = fmt.Errorf("share %d repeated on indexes %d and %d", share.Index, i, j)
			return
		}
		indexes[share.Index] = i
	}

	for i := 0; i < int(k); i++ {
		lambda := pk.Delta
		for j := 0; j < int(k); j++ {
			if i != j {
				lambda.Mul(lambda, big.NewInt(-int64(shares[j].Index)))
				lambda.Div(lambda, big.NewInt(int64(shares[i].Index)-int64(shares[j].Index)))
			}
		}
		twoLambda := new(big.Int).Mul(lambda, two)
		ciToTwoLambda := new(big.Int).Exp(shares[i].Ci, twoLambda, nToSPlusOne)
		cPrime.Mul(cPrime, ciToTwoLambda)
		cPrime.Mod(cPrime, nToSPlusOne)
	}
	L := new(big.Int).Sub(cPrime, one)
	L.Div(L, n)

	bigDec := new(big.Int).Mul(L, pk.Constant)
	bigDec.Mod(bigDec, n)
	dec = bigDec.Bytes()
	return
}

func (pk *PubKey) encryptionProof(message []byte, c *big.Int) (zk ZKProof, err error) {
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
	u, err := pk.randomModNToSPlusOneStar()
	if err != nil {
		return
	}

	// (n+1)^x % n^(s+1)
	nPlusOneToX := new(big.Int).Exp(nPlusOne, x, nToSPlusOne)
	// u^n % n^(s+1)
	uToN := new(big.Int).Exp(u, n, nToSPlusOne)
	// b = (n+1)^x * u^n % n^(s+1)
	b := new(big.Int).Mul(nPlusOneToX, uToN)
	b.Mod(b, nToSPlusOne)

	hash := sha256.New()
	hash.Write(c.Bytes())
	hash.Write(b.Bytes())
	eBytes := hash.Sum(nil)

	e := new(big.Int).SetBytes(eBytes)
	alpha := new(big.Int).SetBytes(message)

	// e*alpha
	eAlpha := new(big.Int).Mul(e, alpha)

	// x + e*alpha
	dummy := new(big.Int).Add(x, eAlpha)
	// (x + e*alpha) % n
	w := new(big.Int).Mod(dummy, n)
	// (x + e*alpha) / n
	t := new(big.Int).Div(dummy, n)

	// s^e
	sToE := new(big.Int).Exp(s, e, nToSPlusOne)
	// u*s^e % n^(s+1)
	uSToE := new(big.Int).Mul(u, sToE)
	uSToE.Mod(uSToE, nToSPlusOne)
	// (n+1)^t % n^(s+1)
	nPlusOneToT := new(big.Int).Exp(nPlusOne, t, nToSPlusOne)

	// u*s^e*(n+1)^t % n^(s+1)
	z := new(big.Int).Mul(uSToE, nPlusOneToT)
	z.Mod(z, nToSPlusOne)

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
	if ca.Cmp(nToSPlusOne) >= 0 || ca.Cmp(zero) < 0 {
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

	hash := sha256.New()
	hash.Write(ca.Bytes())
	hash.Write(c.Bytes())
	hash.Write(d.Bytes())
	hash.Write(a.Bytes())
	hash.Write(b.Bytes())
	e := hash.Sum(nil)

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

func (pk *PubKey) randomModNToS() (r *big.Int, err error) {
	cache := pk.Cache()
	return rand.Int(pk.RandSource, cache.NToS)
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

func (pk *PubKey) randomModNToSPlusOneStar() (r *big.Int, err error) {
	cache := pk.Cache()
	nToSPlusOneMinusOne := new(big.Int).Sub(cache.NToSPlusOne, one)
	r, err = rand.Int(pk.RandSource, nToSPlusOneMinusOne)
	if err != nil {
		return
	}
	r.Add(r, one)
	return
}
