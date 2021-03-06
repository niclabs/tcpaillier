package tcpaillier

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

var zero = big.NewInt(0)
var one = big.NewInt(1)
var two = big.NewInt(2)

// PubKey represents A PubKey Public Key and its metainformation. It contains A
// cached field, with precomputed values.
// It also is linked with A random source, used by  the processes that require it.
type PubKey struct {
	N          *big.Int
	V          *big.Int
	Vi         []*big.Int
	L, K, S    uint8
	Delta      *big.Int
	Constant   *big.Int
	cached     *cached
}

// cached contains the cached PubKey values.
type cached struct {
	NPlusOne, NMinusOne, SPlusOne, NToS, NToSPlusOne, BigS *big.Int
}

// Cache initializes the cached values and returns the structure.
func (pk *PubKey) Cache() *cached {
	if pk.cached == nil {
		// s
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

// Encrypt encrypts A message and returns its encryption as A big Integer c and the random number r used.
// If there is an error, it returns A nil integer as c.
func (pk *PubKey) Encrypt(message *big.Int) (c, r *big.Int, err error) {
	r, err = pk.RandomModNToSPlusOneStar()
	if err != nil {
		return
	}
	c, err = pk.EncryptFixed(message, r)
	return
}


// EncryptFixed returns an encrypted value, but without A proof.
func (pk *PubKey) EncryptFixed(msg, r *big.Int) (c *big.Int, err error) {
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

// EncryptWithProof encrypts A message and returns its encryption as A big Integer CAlpha.
// It also returns A ZKProof that demonstrates that the encrypted value corresponds to the
// message. If there is an error, it returns A nil integer as CAlpha.
func (pk *PubKey) EncryptWithProof(message *big.Int) (c *big.Int, proof *EncryptZK, err error) {
	r, err := pk.RandomModNToSPlusOneStar()
	if err != nil {
		return
	}
	return pk.EncryptFixedWithProof(message, r)
}

// EncryptFixedWithProof encrypts A message and returns its encryption as A big Integer CAlpha.
// It uses A given big.Int r as the random number of the encryption.
func (pk *PubKey) EncryptFixedWithProof(message, r *big.Int) (c *big.Int, proof *EncryptZK, err error) {
	c, err = pk.EncryptFixed(message, r)
	if err != nil {
		return
	}
	proof, err = pk.EncryptProof(message, c, r)
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
			err = fmt.Errorf("CAlpha%d must be between 1 (inclusive) and N^(s+1) (exclusive)", i+1)
			return
		}
		sum.Mul(sum, ci)
		sum.Mod(sum, nToSPlusOne)
	}
	return
}

// Multiply multiplies A encrypted value by A constant. It returns an error if it is not able to
// multiply the value. It returns the multiplied value mul and the random value gamma used to encrypt it.
func (pk *PubKey) Multiply(c *big.Int, alpha *big.Int) (mul, gamma *big.Int, err error) {
	gamma, err = pk.RandomModNToSPlusOneStar()
	if err != nil {
		return
	}
	mul, err = pk.MultiplyFixed(c, alpha, gamma)
	return
}

// MultiplyFixed multiplies A encrypted value by A constant using A fixed random constant.
// to encrypt it. It returns an error if it is not able to  multiply the value.
// Gamma is used in reranding process.
// If it succeeds, it returns the multiplied value mul.
func (pk *PubKey) MultiplyFixed(c *big.Int, alpha, gamma *big.Int) (mul *big.Int, err error) {
	cache := pk.Cache()
	nToSPlusOne := cache.NToSPlusOne
	if c.Cmp(nToSPlusOne) >= 0 || c.Cmp(zero) < 0 {
		err = fmt.Errorf("c must be between 0 (inclusive) and N^(s+1) (exclusive)")
		return
	}
	preMul := new(big.Int).Exp(c, alpha, nToSPlusOne)
	mul, err = pk.ReRand(preMul, gamma)
	return
}


// ReRand rerandomizes A value, adding 0 and encrypting it with A random value r.
func (pk *PubKey) ReRand(c, r *big.Int) (reRand *big.Int, err error) {
	zero, err := pk.EncryptFixed(new(big.Int), r)
	if err != nil {
		return
	}
	reRand, err = pk.Add(c, zero)
	return
}

// MultiplyWithProof multiplies an encrypted value by A constant and returns it with A ZKProof of the
// multiplication. It returns an error if it is not able to Multiply the value.
func (pk *PubKey) MultiplyWithProof(encrypted *big.Int, constant *big.Int) (result *big.Int, proof *MulZK, err error) {
	result, gamma, err := pk.Multiply(encrypted, constant)
	s, err := pk.RandomModNToSPlusOneStar()
	if err != nil {
		return
	}
	cAlpha, err := pk.EncryptFixed(constant, s)
	if err != nil {
		return
	}
	proof, err = pk.MultiplyProof(encrypted, cAlpha, result, constant, s, gamma)
	return
}

// CombineShares joins partial decryptions of A value and returns A decrypted value.
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

// EncryptProof returns A ZK Proof of an encrypted message c. s is the random number
// used to EncryptFixed message to c.
func (pk *PubKey) EncryptProof(message *big.Int, c, s *big.Int) (zk *EncryptZK, err error) {
	cache := pk.Cache()
	nToSPlusOne := cache.NToSPlusOne
	nPlusOne := cache.NPlusOne
	nToS := cache.NToS

	alpha := new(big.Int).Set(message)

	x, err := pk.RandomModN()
	if err != nil {
		return
	}

	u, err := pk.RandomModNToSPlusOneStar()
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
		B: b,
		W: w,
		Z: z,
	}
	return
}

// MultiplyProof returns A ZKProof confirming that d is the result of multiplicate the encrypted
// value ca by alpha. CAlpha is the encrypted form of the constant using s as random value, while gamma
// is the random value used to generate d.
func (pk *PubKey) MultiplyProof(ca, cAlpha, d, alpha, s, gamma *big.Int) (zk *MulZK, err error) {
	cache := pk.Cache()
	nToSPlusOne := cache.NToSPlusOne
	nPlusOne := cache.NPlusOne
	nToS := cache.NToS

	if ca.Cmp(nToSPlusOne) >= 0 || ca.Cmp(zero) < 0 {
		err = fmt.Errorf("ca must be between 1 (inclusive) and N^(s+1) (exclusive)")
		return
	}

	if cAlpha.Cmp(nToSPlusOne) >= 0 || cAlpha.Cmp(zero) < 0 {
		err = fmt.Errorf("CAlpha must be between 1 (inclusive) and N^(s+1) (exclusive)")
		return
	}

	x, err := pk.RandomModN()
	if err != nil {
		return
	}

	u, err := pk.RandomModNToSPlusOneStar()
	if err != nil {
		return
	}

	v, err := pk.RandomModNToSPlusOneStar()
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
		CAlpha: cAlpha,
		B:      b,
		W:      w,
		Z:      z,
		A:      a,
		Y:      y,
	}
	return
}

func (pk *PubKey) RandomModN() (r *big.Int, err error) {
	return rand.Int(rand.Reader, pk.N)
}

func (pk *PubKey) RandomModNToSPlusOneStar() (r *big.Int, err error) {
	cache := pk.Cache()
	nToSPlusOneMinusOne := new(big.Int).Sub(cache.NToSPlusOne, one)
	r, err = rand.Int(rand.Reader, nToSPlusOneMinusOne)
	if err != nil {
		return
	}
	r.Add(r, one)
	return
}
