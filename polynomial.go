package tcpaillier

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

// polynomial represents a classic polynomial, with convenience methods useful for
// the operations the Threshold Cryptography library needs.
type polynomial []*big.Int

// newPolynomial creates a polynomial of degree d with all its d+1 coefficients in 0.
func newPolynomial(d int) polynomial {
	poly := make(polynomial, d+1)
	for i := 0; i < len(poly); i++ {
		poly[i] = new(big.Int)
	}
	return poly
}

// GetDegree returns the degree of a polynomial, which is the length of the coefficient
// array, minus 1.
func (p polynomial) getDegree() int {
	return len(p) - 1
}

// createRandomPolynomial creates a polynomial of degree "d" with random coefficients as terms
// with degree greater than 1. The coefficient of the term of degree 0 is x0 and the module for all the
// coefficients of the polynomial is m.
func createRandomPolynomial(d int, x0, m *big.Int) (polynomial, error) {
	if m.Sign() < 0 {
		return polynomial{}, fmt.Errorf("m is negative")
	}
	poly := newPolynomial(d)

	poly[0].Set(x0)

	for i := 1; i < len(poly); i++ {
		r, err := rand.Int(rand.Reader, m)
		if err != nil {
			return polynomial{}, err
		}
		poly[i] = r
	}
	return poly, nil
}

// eval evaluates a polynomial to x with Horner's method and returns the result.
func (p polynomial) eval(x *big.Int) *big.Int {
	y := big.NewInt(0)
	for k := len(p) - 1; k >= 0; k-- {
		y.Mul(y, x)
		y.Add(y, p[k])
	}
	return y
}

// string returns the polynomial formatted as a string.
func (p polynomial) String() string {
	s := make([]string, len(p))
	for i := 0; i < len(p); i++ {
		s[i] = fmt.Sprintf("%dx^%d", p[i], i)
	}
	return strings.Join(s, " + ")
}
