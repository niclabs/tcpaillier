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

func (pk *PubKey) encrypt(msg, r *big.Int) (c *big.Int, err error) {
	cache := pk.Cache()
	// n+1
	nPlusOne := cache.NPlusOne
	// n^s
	nToS := cache.NToS
	// n^(s+1)
	nToSPlusOne := cache.NToSPlusOne
	// (n+1)^m % n^(s+1)
	m := new(big.Int).Mod(msg, nToSPlusOne)
	nPlusOneToM := new(big.Int).Exp(nPlusOne, m, nToSPlusOne)
	// r^(n^s) % n^(s+1)
	rToNToS := new(big.Int).Exp(r, nToS, nToSPlusOne)
	// (n+1)^m * r^(n^s) % n^(s+1)
	c = new(big.Int).Mul(nPlusOneToM, rToNToS)
	c.Mod(c, nToSPlusOne)
	return
}

// Encrypt encrypts a message and returns its encryption as a big Integer cAlpha.
// It also returns a ZKProof that demonstrates that the encrypted value corresponds to the
// message. If there is an error, it returns a nil integer as cAlpha.
func (pk *PubKey) Encrypt(message *big.Int) (c *big.Int, proof ZKProof, err error) {
	r, err := pk.randomModNToSPlusOneStar()
	if err != nil {
		return
	}
	return pk.EncryptFixed(message, r)
}

// EncryptFixed encrypts a message and returns its encryption as a big Integer cAlpha.
// It uses a given big.Int r as the random number of the encryption.
func (pk *PubKey) EncryptFixed(message, r *big.Int) (c *big.Int, proof ZKProof, err error) {
	c, err = pk.encrypt(message, r)
	if err != nil {
		return
	}
	proof, err = pk.encryptionProof(message, c, r)
	if err != nil {
		return
	}
	return
}

// Add adds an indeterminate number of encrypted values and returns its encrypted sum, or an error
// if the value cannot be determined.
func (pk *PubKey) Add(cList ...*big.Int) (sum *big.Int, err error) {
	if len(cList) == 0 {
		err = fmt.Errorf("empty encrypted list")
		return
	}
	cache := pk.Cache()
	nToSPlusOne := cache.NToSPlusOne
	sum = new(big.Int).Set(cList[0])
	for i := 1; i < len(cList); i++ {
		ci := cList[i]
		if ci.Cmp(nToSPlusOne) >= 0 || ci.Cmp(zero) < 1 {
			err = fmt.Errorf("cAlpha%d must be between 1 (inclusive) and N^(s+1) (exclusive)", i+1)
			return
		}
		sum.Mul(sum, ci)
		sum.Mod(sum, nToSPlusOne)
	}
	return
}

// multiply multiplies a encrypted value by a constant. It returns an error if it is not able to
// multiply the value.
func (pk *PubKey) multiply(c *big.Int, alpha *big.Int) (mul, gamma *big.Int, err error) {
	cache := pk.Cache()
	nToSPlusOne := cache.NToSPlusOne
	if c.Cmp(nToSPlusOne) >= 0 || c.Cmp(zero) < 0 {
		err = fmt.Errorf("cAlpha must be between 0 (inclusive) and N^(s+1) (exclusive)")
		return
	}
	preMul := new(big.Int).Exp(c, alpha, nToSPlusOne)
	gamma, err = pk.randomModNToSPlusOneStar()
	if err != nil {
		return
	}
	zero, err := pk.encrypt(new(big.Int), gamma)
	mul, err = pk.Add(preMul, zero)
	return
}

// Multiply multiplies an encrypted value by a constant and returns it with a ZKProof of the
// multiplication. It returns an error if it is not able to multiply the value.
func (pk *PubKey) Multiply(encrypted *big.Int, constant *big.Int) (d *big.Int, proof ZKProof, err error) {
	d, gamma, err := pk.multiply(encrypted, constant)
	s, err := pk.randomModNToSPlusOneStar()
	if err != nil {
		return
	}
	cAlpha, err := pk.encrypt(constant, s)
	if err != nil {
		return
	}
	proof, err = pk.multiplicationProof(encrypted, cAlpha, d, constant, s, gamma)
	return
}

// CombineShares joins partial decryptions of a value and returns a decrypted value.
// It checks that the number of values is equal or more than the threshold.
func (pk *PubKey) CombineShares(shares ...*DecryptionShare) (dec *big.Int, err error) {
	n := pk.N
	k := int(pk.K)
	cache := pk.Cache()
	nToSPlusOne := cache.NToSPlusOne

	if len(shares) < k {
		err = fmt.Errorf("needed %d shares to decrypt, but got %d", pk.K, len(shares))
		return
	}

	shares = shares[:pk.K]

	// Check for repeated shares
	indexes := make(map[uint8]int)
	for i, share := range shares {
		if j, ok := indexes[share.Index]; ok {
			err = fmt.Errorf("share %d repeated on indexes %d and %d", share.Index, i, j)
			return
		}
		indexes[share.Index] = i
	}

	cPrime := new(big.Int).Set(one)

	for _, share := range shares {
		num := new(big.Int).Set(pk.Delta) // Lambda is multiplied by two, we are doing that now.
		den := new(big.Int).Set(one)
		for _, sharePrime := range shares {
			if share.Index != sharePrime.Index {
				num.Mul(num, big.NewInt(int64(sharePrime.Index)))
				den.Mul(den, big.NewInt(int64(sharePrime.Index)-int64(share.Index)))
			}
		}
		lambda2 := new(big.Int)
		lambda2.Mul(num, two).Quo(lambda2, den)
		CiToLambda2 := new(big.Int).Exp(share.Ci, lambda2, nToSPlusOne)
		cPrime.Mul(cPrime, CiToLambda2).Mod(cPrime, nToSPlusOne)
	}

	l := new(big.Int)
	l.Sub(cPrime, one).Div(l, n)
	bigDec := new(big.Int).Mul(pk.Constant, l)
	bigDec.Mod(bigDec, n)
	dec = bigDec
	return
}

func (pk *PubKey) encryptionProof(message *big.Int, c, s *big.Int) (zk ZKProof, err error) {
	cache := pk.Cache()
	nToSPlusOne := cache.NToSPlusOne
	nPlusOne := cache.NPlusOne
	nToS := cache.NToS

	alpha := new(big.Int).Set(message)

	x, err := pk.randomModN()
	if err != nil {
		return
	}

	u, err := pk.randomModNToSPlusOneStar()
	if err != nil {
		return
	}

	nPlusOneToX := new(big.Int).Exp(nPlusOne, x, nToSPlusOne)
	uToN := new(big.Int).Exp(u, nToS, nToSPlusOne)
	b := new(big.Int)
	b.Mul(nPlusOneToX, uToN).Mod(b, nToSPlusOne)

	hash := sha256.New()
	hash.Write(c.Bytes())
	hash.Write(b.Bytes())
	eBytes := hash.Sum(nil)

	e := new(big.Int).SetBytes(eBytes)

	eAlpha := new(big.Int).Mul(e, alpha)

	dummy := new(big.Int).Add(x, eAlpha)
	w := new(big.Int).Mod(dummy, nToS)
	t := new(big.Int).Div(dummy, nToS)

	sToE := new(big.Int).Exp(s, e, nToSPlusOne)
	nPlusOneToT := new(big.Int).Exp(nPlusOne, t, nToSPlusOne)
	z := new(big.Int)
	z.Mul(u, sToE).Mul(z, nPlusOneToT).Mod(z, nToSPlusOne)

	zk = &EncryptZK{
		c: c,
		b: b,
		w: w,
		z: z,
	}
	return
}

func (pk *PubKey) multiplicationProof(ca, cAlpha, d, alpha, s, gamma *big.Int) (zk ZKProof, err error) {
	cache := pk.Cache()
	nToSPlusOne := cache.NToSPlusOne
	nPlusOne := cache.NPlusOne
	nToS := cache.NToS

	if ca.Cmp(nToSPlusOne) >= 0 || ca.Cmp(zero) < 0 {
		err = fmt.Errorf("ca must be between 1 (inclusive) and N^(s+1) (exclusive)")
		return
	}

	if cAlpha.Cmp(nToSPlusOne) >= 0 || cAlpha.Cmp(zero) < 0 {
		err = fmt.Errorf("cAlpha must be between 1 (inclusive) and N^(s+1) (exclusive)")
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

	v, err := pk.randomModNToSPlusOneStar()
	if err != nil {
		return
	}

	caToX := new(big.Int).Exp(ca, x, nToSPlusOne)
	vToNToS := new(big.Int).Exp(v, nToS, nToSPlusOne)
	a := new(big.Int)
	a.Mul(caToX, vToNToS).Mod(a, nToSPlusOne)

	nPlusOneToX := new(big.Int).Exp(nPlusOne, x, nToSPlusOne)
	uToNToS := new(big.Int).Exp(u, nToS, nToSPlusOne)
	b := new(big.Int)
	b.Mul(nPlusOneToX, uToNToS).Mod(b, nToSPlusOne)

	hash := sha256.New()
	hash.Write(ca.Bytes())
	hash.Write(cAlpha.Bytes())
	hash.Write(d.Bytes())
	hash.Write(a.Bytes())
	hash.Write(b.Bytes())
	eBytes := hash.Sum(nil)

	e := new(big.Int).SetBytes(eBytes)

	eAlpha := new(big.Int).Mul(e, alpha)

	dummy := new(big.Int).Add(x, eAlpha)
	w := new(big.Int).Mod(dummy, nToS)
	t := new(big.Int).Div(dummy, nToS)

	sToE := new(big.Int).Exp(s, e, nToSPlusOne)
	nPlusOneToT := new(big.Int).Exp(nPlusOne, t, nToSPlusOne)
	z := new(big.Int)
	z.Mul(u, sToE).Mul(z, nPlusOneToT).Mod(z, nToSPlusOne)

	caToT := new(big.Int).Exp(ca, t, nToSPlusOne)
	gammaToE := new(big.Int).Exp(gamma, e, nToSPlusOne)
	y := new(big.Int)
	y.Mul(v, caToT).Mul(y, gammaToE).Mod(y, nToSPlusOne)

	zk = &MulZK{
		cAlpha: cAlpha,
		ca:     ca,
		d:      d,
		b:      b,
		w:      w,
		z:      z,
		a:      a,
		y:      y,
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
