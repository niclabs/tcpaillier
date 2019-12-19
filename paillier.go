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
func GenKeyShares(bitSize int, s, l, k uint8, randSource io.Reader) (skList []*KeyShare, viArray []*big.Int, err error) {
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

	// Init big numbers
	m := new(big.Int)
	n := new(big.Int)
	nToSPlusOne := new(big.Int)
	nm := new(big.Int)
	v := new(big.Int)
	d := new(big.Int)
	r := new(big.Int)
	delta := new(big.Int)
	deltaSquare := new(big.Int)

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

	n.Mul(p, q)
	m.Mul(p1, q1)
	nm.Mul(m, n)
	nToSPlusOne.Exp(n, sPlusOne, nil)

	d.Mul(m, new(big.Int).ModInverse(m, n))

	// Generate polynomial with random coefficients.
	var poly polynomial
	poly, err = createRandomPolynomial(int(k-1), d, m, randSource)

	if err != nil {
		return
	}

	// generate V
	ok := false
	divisor := new(big.Int)
	one := big.NewInt(1)
	for !ok {
		r, err = randInt(4*n.BitLen(), randSource)
		if err != nil {
			return
		}
		divisor.GCD(nil, nil, r, n)
		if one.Cmp(divisor) != 0 {
			ok = true
		}
	}

	v.Mul(r, r).Mod(v, nToSPlusOne)

	delta.MulRange(1, int64(l))
	deltaSquare.Mul(delta, delta)

	constant := big.NewInt(4)
	constant.Mul(constant, deltaSquare).ModInverse(constant, n)

	skList = make([]*KeyShare, l)
	viArray = make([]*big.Int, l)

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
		si := poly.eval(big.NewInt(int64(i)))
		si.Mod(si, nm)
		skList[i] = &KeyShare{
			PubKey: pubKey,
			Index:  i,
			Si:     si,
		}
		deltaSi := new(big.Int).Mul(si, delta)
		viArray[i] = new(big.Int).Exp(v, deltaSi, nToSPlusOne)
	}
	return
}
