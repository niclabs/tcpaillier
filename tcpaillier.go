// Package tcpaillier is a Threshold PubKey library, based on the Java Implementation.
// of Threshold PubKey Toolbox [1].

// [1] http://www.cs.utdallas.edu/dspl/cgi-bin/pailliertoolbox/index.php
package tcpaillier

import (
	"fmt"
	"math/big"
)

const c = 25

type FixedParams struct {
	P, P1, Q, Q1 *big.Int
}

func (fp *FixedParams) Validate() bool {
	p1 := new(big.Int).Rsh(fp.P, 1)
	q1 := new(big.Int).Rsh(fp.Q, 1)
	return fp.P.ProbablyPrime(c) &&
		fp.Q.ProbablyPrime(c) &&
		fp.P1.ProbablyPrime(c) &&
		fp.Q1.ProbablyPrime(25) &&
		p1.Cmp(fp.P1) == 0 && q1.Cmp(fp.Q1) == 0
}

func (fp *FixedParams) String() string {
	return fmt.Sprintf("P: %s\nq: %s\np1: %s\nq1: %s\n", fp.P, fp.Q, fp.P1, fp.Q1)
}

// NewKey returns a list of l keyshares of bitSize bits of length, with a threshold of
// k and using an s parameter of s in PubKey. It uses randSource
// as a random source. It also uses a list of fixed params as the primes needed for the scheme.
func NewFixedKey(bitSize int, s, l, k uint8, params *FixedParams) (keyShares []*KeyShare, pubKey *PubKey, err error) {
	// Parameter checking
	if bitSize < 64 {
		err = fmt.Errorf("bitSize should be at least 64 bits, but it is %d", bitSize)
		return
	}
	if s < 1 {
		err = fmt.Errorf("s should be at least 1, but it is %d", s)
	}
	if l <= 1 {
		err = fmt.Errorf("L should be greater than 1, but it is %d", l)
		return
	}
	if k <= 0 {
		err = fmt.Errorf("K should be greater than 0, but it is %d", k)
		return
	}
	if k < (l/2+1) || k > l {
		err = fmt.Errorf("K should be between %d and %d, but it is %d", (l/2)+1, l, k)
		return
	}

	bigS := big.NewInt(int64(s))
	sPlusOne := new(big.Int).Add(bigS, one)

	n := new(big.Int).Mul(params.P, params.Q)
	m := new(big.Int).Mul(params.P1, params.Q1)
	nm := new(big.Int).Mul(n, m)
	nToS := new(big.Int).Exp(n, bigS, nil)
	nToSPlusOne := new(big.Int).Exp(n, sPlusOne, nil)

	mInv := new(big.Int).ModInverse(m, n)
	d := new(big.Int).Mul(m, mInv)

	// Generate polynomial with random coefficients.
	var poly polynomial
	poly, err = createRandomPolynomial(int(k-1), d, nm)

	if err != nil {
		return
	}

	// generate Vi with Shoup heuristic
	var r *big.Int
	for {
		r, err = RandomInt(4*bitSize)
		if err != nil {
			return
		}
		gcd := new(big.Int).GCD(nil, nil, r, n)
		if one.Cmp(gcd) == 0 {
			break
		}
	}

	v := new(big.Int).Mul(r, r)
	v.Mod(v, nToSPlusOne)

	delta := new(big.Int).MulRange(1, int64(l))
	deltaSquare := new(big.Int).Mul(delta, delta)
	constant := new(big.Int)
	constant.Mul(big.NewInt(4), deltaSquare).ModInverse(constant, nToS)

	keyShares = make([]*KeyShare, l)

	pubKey = &PubKey{
		N:          n,
		S:          s,
		V:          v,
		Constant:   constant,
		Delta:      delta,
		L:          l,
		Vi:         make([]*big.Int, l),
		K:          k,
	}

	var index uint8
	for index = 0; index < l; index++ {
		x := index + 1
		si := poly.eval(big.NewInt(int64(x)))
		si.Mod(si, nm)
		keyShares[index] = &KeyShare{
			PubKey: pubKey,
			Index:  x,
			Si:     si,
		}
		deltaSi := new(big.Int).Mul(si, delta)
		pubKey.Vi[index] = new(big.Int).Exp(v, deltaSi, nToSPlusOne)
	}
	return
}

// NewKey returns a list of l keyshares of bitSize bits of length, with a threshold of
// k and using an s parameter of s in PubKey. It uses randSource
// as a random source. If randSource is undefined, it uses crypto/rand
// reader.
func NewKey(bitSize int, s, l, k uint8) (keyShares []*KeyShare, pubKey *PubKey, err error) {

	pPrimeSize := (bitSize + 1) / 2
	qPrimeSize := bitSize - pPrimeSize

	p, p1, err := GenerateSafePrimes(pPrimeSize,)
	if err != nil {
		return
	}

	var q, q1 *big.Int
	for {
		q, q1, err = GenerateSafePrimes(qPrimeSize)
		if err != nil {
			return
		}
		if p.Cmp(q) != 0 && p.Cmp(q1) != 0 && q.Cmp(p1) != 0 {
			break
		}
	}
	return NewFixedKey(bitSize, s, l, k, &FixedParams{p, p1, q, q1,})
}
