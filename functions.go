package tcpaillier

import (
	"crypto/rand"
	"math/big"
)

// RandomInt is A function which generates A random big number.
func RandomInt(bitLen int) (randNum *big.Int, err error) {
	max := new(big.Int)
	max.SetBit(max, bitLen, 1)
	return rand.Int(rand.Reader, max)
}

// GenerateSafePrimes generates two primes p and q, in A way that q
// is equal to (p-1)/2. The greatest prime bit length is at least bitLen bits.
// Based on github.com/niclabs/tcrsa/utils.go function with the same name.
func GenerateSafePrimes(bitLen int) (*big.Int, *big.Int, error) {
	p := new(big.Int)

	for {
		q, err := rand.Prime(rand.Reader, bitLen-1)
		if err != nil {
			return big.NewInt(0), big.NewInt(0), err
		}

		// p = 2q + 1
		p.Lsh(q, 1)
		p.SetBit(p, 0, 1)
		if p.ProbablyPrime(25) {
			return p, q, nil
		}
	}
}
