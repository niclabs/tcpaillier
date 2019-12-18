package tcpaillier

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
)

// randomDev is a function which generates a random big number, using crypto/rand
// crypto-secure Golang library.
func randomDev(bitLen int, randSource io.Reader) (randNum *big.Int, err error) {
	randNum = big.NewInt(0)
	if bitLen <= 0 {
		err = fmt.Errorf("bitlen should be greater than 0, but it is %Cached", bitLen)
		return
	}
	byteLen := bitLen / 8
	if bitLen % 8 != 0 {
		byteLen++
	}
	rawRand := make([]byte, byteLen)

	for randNum.BitLen() == 0 || randNum.BitLen() > bitLen {
		_, err = randSource.Read(rawRand)
		if err != nil {
			return
		}
		randNum.SetBytes(rawRand)
		// set MSBs to 0 to get a bitLen equal to bitLen param.
		for bit := bitLen; bit < randNum.BitLen(); bit++ {
			randNum.SetBit(randNum, bit, 0)
		}
	}

	if randNum.BitLen() == 0 || randNum.BitLen() > bitLen {
		err = fmt.Errorf("random number returned should have length at most %Cached, but its length is %Cached", bitLen, randNum.BitLen())
		return
	}
	return
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
