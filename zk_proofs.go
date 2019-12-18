package tcpaillier

import (
	"crypto"
	"fmt"
	"math/big"
)

type ZKProof interface {
	Verify() error
}

type EncryptZK struct {
	c, b, w, z, n, nToSPlusOne *big.Int
}

func (zk *EncryptZK) Verify() error {

	nPlusOne := new(big.Int).Add(zk.n, one)
	sha256 := crypto.SHA256.New()

	sha256.Write(zk.c.Bytes())
	sha256.Write(zk.b.Bytes())
	e := sha256.Sum(nil)
	bigE := new(big.Int).SetBytes(e)


	nPlusOneToW := new(big.Int).Exp(nPlusOne, zk.w, zk.nToSPlusOne)
	zToN := new(big.Int).Exp(zk.z, zk.n, zk.nToSPlusOne)

	left := new(big.Int).Mul(nPlusOneToW, zToN)
	left.Mod(left, zk.nToSPlusOne)


	cToE := new(big.Int).Exp(zk.c, bigE, zk.nToSPlusOne)
	right := new(big.Int).Mul(zk.b, cToE)
	right.Mod(right, zk.nToSPlusOne)

	if left.Cmp(right) != 0 {
		return fmt.Errorf("verification failed")
	}
	return nil
}
