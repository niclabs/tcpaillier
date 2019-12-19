// Package tcpaillier is a Threshold Paillier library, based on the Java Implementation.
// of Threshold Paillier Toolbox [1].
// [1] http://www.cs.utdallas.edu/dspl/cgi-bin/pailliertoolbox/index.php
package tcpaillier

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
)

// GenKeyShares returns a list of l keyshares, with a threshold of
// k and using an S parameter of s in Paillier. It uses randSource
// as a random source. If randSource is undefined, it uses crypto/rand
// reader.
func GenKeyShares(bitSize int, s, l, k uint8, randSource io.Reader) (keyShares []*KeyShare, err error) {
	if randSource == nil {
		randSource = rand.Reader
	}
	// Parameter checking
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

	pPrimeSize := (bitSize + 1) / 2
	qPrimeSize := bitSize - pPrimeSize - 1

	bigS := big.NewInt(int64(s))
	sPlusOne := new(big.Int).Add(bigS, one)

	p, p1, err := generateSafePrimes(pPrimeSize, randSource)
	if err != nil {
		return
	}

	q, q1, err := generateSafePrimes(qPrimeSize, randSource)
	if err != nil {
		return
	}

	n := new(big.Int).Mul(p, q)
	m := new(big.Int).Mul(p1, q1)
	nm := new(big.Int).Mul(n, m)
	nToSPlusOne := new(big.Int).Exp(n, sPlusOne, nil)

	mInv := new(big.Int).ModInverse(m, n)
	d := new(big.Int).Mul(m, mInv)

	// Generate polynomial with random coefficients.
	var poly polynomial
	poly, err = createRandomPolynomial(int(k-1), d, nm, randSource)

	if err != nil {
		return
	}

	// generate V with Shoup heuristic
	var r *big.Int
	for {
		r, err = randInt(4*bitSize, randSource)
		if err != nil {
			return
		}
		if one.Cmp(new(big.Int).GCD(nil, nil, r, n)) == 0 {
			break
		}
	}

	v := new(big.Int).Mul(r, r)
	v.Mod(v, nToSPlusOne)

	delta := new(big.Int).MulRange(1, int64(l))
	deltaSquare := new(big.Int).Mul(delta, delta)

	constant := big.NewInt(4)
	constant.Mul(constant, deltaSquare).ModInverse(constant, n)

	keyShares = make([]*KeyShare, l)

	pubKey := &PubKey{
		N:          n,
		S:          s,
		V:          v,
		Constant:   constant,
		Delta:      delta,
		L:          l,
		Vi:         make([]*big.Int, l),
		K:          k,
		RandSource: randSource,
	}

	var i uint8
	for i = 0; i < l; i++ {
		index := i + 1
		si := poly.eval(big.NewInt(int64(index)))
		si.Mod(si, nm)
		keyShares[i] = &KeyShare{
			PubKey: pubKey,
			Index:  index,
			Si:     si,
		}
		deltaSi := new(big.Int).Mul(si, delta)
		pubKey.Vi[i] = new(big.Int).Exp(v, deltaSi, nToSPlusOne)
	}
	return
}
