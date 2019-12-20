package tcpaillier

import (
	"crypto/rand"
	"io"
	"math/big"
)

// randInt is a function which generates a random big number.
func randInt(bitLen int, randSource io.Reader) (randNum *big.Int, err error) {
	max := new(big.Int)
	max.SetBit(max, bitLen, 1)
	return rand.Int(randSource, max)
}

// generateSafePrimes generates two primes p and q, in a way that q
// is equal to (p-1)/2. The greatest prime bit length is at least bitLen bits.
// Based on github.com/niclabs/tcrsa/utils.go function with the same name.
func generateSafePrimes(bitLen int, randSource io.Reader) (*big.Int, *big.Int, error) {
	p := new(big.Int)

	for {
		q, err := rand.Prime(randSource, bitLen-1)
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
