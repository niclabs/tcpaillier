// Tests from github.com/niclabs/tcrsa
package tcpaillier

import (
	"crypto/rand"
	"math/big"
	"testing"
)

const polynomialTestDegree = 3

// Tests the degree of the polynomial created is equal to the argument provided.
func TestPolynomial(t *testing.T) {
	p := newPolynomial(polynomialTestDegree)
	if p.getDegree() != polynomialTestDegree {
		t.Errorf("degree of polynomial is not the provided")
	}
}

func TestCreateRandomPolynomial(t *testing.T) {
	p, err := createRandomPolynomial(polynomialTestDegree, big.NewInt(10), big.NewInt(1024), rand.Reader)
	if err != nil {
		t.Errorf("could not create a random polynomial")
		return
	}
	if p.getDegree() != polynomialTestDegree {
		t.Errorf("degree of polynomial is not the provided")
	}

}

func TestPolynomial_Eval(t *testing.T) {
	p := newPolynomial(polynomialTestDegree)
	p[3] = big.NewInt(7)
	p[2] = big.NewInt(5)
	p[1] = big.NewInt(9)
	p[0] = big.NewInt(1)

	expected := big.NewInt(7591)

	res := p.eval(big.NewInt(10))

	if expected.Cmp(res) != 0 {
		t.Errorf("The evaluations is not providing a correct result")
	}
}
