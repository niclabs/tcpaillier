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
	q := new(big.Int)
	r := new(big.Int)

	for {
		p, err := rand.Prime(randSource, bitLen)
		if err != nil {
			return big.NewInt(0), big.NewInt(0), err
		}
		// If the number will be odd after right shift
		if p.Bit(1) == 1 {
			// q = (p - 1) / 2
			q.Rsh(p, 1)
			if q.ProbablyPrime(25) {
				return p, q, nil
			}
		}

		if p.BitLen() < bitLen {
			// r = 2p + 1
			r.Lsh(p, 1)
			r.SetBit(r, 0, 1)
			if r.ProbablyPrime(25) {
				return r, p, nil
			}
		}
	}
}
