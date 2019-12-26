package tcpaillier_test

import (
	"crypto/rand"
	"fmt"
	"github.com/niclabs/tcpaillier"
	"math/big"
	"testing"
)

const k = 3
const l = 5
const s = 2

const bitSize = 512

var twelve = big.NewInt(12)
var twentyFive = big.NewInt(25)
var fortyNine = big.NewInt(49)
var threeHundred = big.NewInt(300)

func TestGenKeyShares(t *testing.T) {
	shares, _, err := tcpaillier.NewKey(bitSize, s, l, k, rand.Reader)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if len(shares) != l {
		t.Errorf("length of shares is %d instead of %d", len(shares), l)
		return
	}
	indexes := make(map[uint8]struct{})
	for i, share := range shares {
		if int(share.Index) != i+1 {
			t.Errorf("index should have been %d but it is %d", i, share.Index)
			return
		}
		if _, ok := indexes[share.Index]; ok {
			t.Errorf("index repeated: %d", share.Index)
			return
		}
		indexes[share.Index] = struct{}{}
	}
}

func TestPubKey_Encrypt(t *testing.T) {
	shares, pk, err := tcpaillier.NewKey(bitSize, s, l, k, rand.Reader)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	encrypted, zk, err := pk.Encrypt(twelve)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying encryption ZKProof: %v", err)
		return
	}
	decryptShares := make([]*tcpaillier.DecryptionShare, l)
	for i, share := range shares {
		decryptShare, err := share.DecryptProof(encrypted)
		if err != nil {
			t.Errorf("share %d is not able to decrypt partially the message: %v", share.Index, err)
			return
		}
		if err := decryptShare.Verify(pk); err != nil {
			t.Errorf("error verifying decryption ZKProof: %v", err)
			return
		}
		decryptShares[i] = decryptShare
	}
	decrypted, err := pk.CombineShares(decryptShares...)
	if err != nil {
		t.Errorf("cannot combine shares: %v", err)
		return
	}
	if decrypted.Cmp(twelve) != 0 {
		t.Errorf("messages are different. Decrypted is %s and twelve was %s.", decrypted, twelve)
		return
	}
}

func TestPubKey_Add(t *testing.T) {
	shares, pk, err := tcpaillier.NewKey(bitSize, s, l, k, rand.Reader)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	encrypted, zk, err := pk.Encrypt(twelve)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying first encryption ZKProof: %v", err)
		return
	}
	encrypted2, zk, err := pk.Encrypt(twentyFive)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying second encryption ZKProof: %v", err)
		return
	}

	encryptedSum, err := pk.Add(encrypted, encrypted2, encrypted)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	decryptShares := make([]*tcpaillier.DecryptionShare, l)
	for i, share := range shares {
		decryptShare, err := share.DecryptProof(encryptedSum)
		if err != nil {
			t.Errorf("share %d is not able to decrypt partially the message: %v", share.Index, err)
			return
		}
		if err := decryptShare.Verify(pk); err != nil {
			t.Errorf("error verifying decryption ZKProof: %v", err)
			return
		}
		decryptShares[i] = decryptShare
	}
	decrypted, err := pk.CombineShares(decryptShares...)
	if err != nil {
		t.Errorf("cannot combine shares: %v", err)
		return
	}
	if decrypted.Cmp(fortyNine) != 0 {
		t.Errorf("messages are different. Decrypted is %d but should have been %s.", decrypted, fortyNine)
		return
	}
}

func TestPubKey_AddNegative(t *testing.T) {
	shares, pk, err := tcpaillier.NewKey(bitSize, s, l, k, rand.Reader)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	minusTwelve := new(big.Int).Neg(twelve)
	minusTwelve.Mod(minusTwelve, pk.Cache().NToSPlusOne)
	encrypted, zk, err := pk.Encrypt(minusTwelve)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying first encryption ZKProof: %v", err)
		return
	}
	minusTwentyFive := new(big.Int).Neg(twentyFive)
	minusTwentyFive.Mod(minusTwentyFive, pk.Cache().NToSPlusOne)
	encrypted2, zk, err := pk.Encrypt(minusTwentyFive)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying second encryption ZKProof: %v", err)
		return
	}

	encryptedSum, err := pk.Add(encrypted, encrypted2)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	sum := new(big.Int).Add(minusTwelve, minusTwentyFive)
	sum.Mod(sum, pk.N)
	decryptShares := make([]*tcpaillier.DecryptionShare, l)
	for i, share := range shares {
		decryptShare, err := share.DecryptProof(encryptedSum)
		if err != nil {
			t.Errorf("share %d is not able to decrypt partially the message: %v", share.Index, err)
			return
		}
		if err := decryptShare.Verify(pk); err != nil {
			t.Errorf("error verifying decryption ZKProof: %v", err)
			return
		}
		decryptShares[i] = decryptShare
	}
	decrypted, err := pk.CombineShares(decryptShares...)
	if err != nil {
		t.Errorf("cannot combine shares: %v", err)
		return
	}
	if decrypted.Cmp(sum) != 0 {
		t.Errorf("messages are different:\nDecrypted = %s\n Expected = %s.", decrypted, sum)
		return
	}
}


func TestPubKey_Multiply(t *testing.T) {
	shares, pk, err := tcpaillier.NewKey(bitSize, s, l, k, rand.Reader)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	encrypted, zk, err := pk.Encrypt(twelve)
	if err != nil {
		t.Errorf("error encrypting twelve: %v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying first encryption ZKProof: %v", err)
		return
	}

	encryptedMul, proof, err := pk.Multiply(encrypted, twentyFive)
	if err != nil {
		t.Errorf("Error multiplying twelve for constant %s: %v", twentyFive, err)
		return
	}

	if err := proof.Verify(pk); err != nil {
		t.Errorf("Error verifying mulZKProof: %v", err)
		return
	}

	decryptShares := make([]*tcpaillier.DecryptionShare, l)
	for i, share := range shares {
		decryptShare, err := share.DecryptProof(encryptedMul)
		if err != nil {
			t.Errorf("share %d is not able to decrypt partially the message: %v", share.Index, err)
			return
		}
		if err := decryptShare.Verify(pk); err != nil {
			t.Errorf("error verifying decryption ZKProof: %v", err)
			return
		}
		decryptShares[i] = decryptShare
	}
	decrypted, err := pk.CombineShares(decryptShares...)
	if err != nil {
		t.Errorf("cannot combine shares: %v", err)
		return
	}
	if decrypted.Cmp(threeHundred) != 0 {
		t.Errorf("messages are different. Decrypted is %d but should have been %s.", decrypted, threeHundred)
		return
	}
}

func TestPubKey_RandAdd(t *testing.T) {
	shares, pk, err := tcpaillier.NewKey(bitSize, s, l, k, rand.Reader)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	maxRand := new(big.Int).Rsh(pk.N, 1)
	rand1, err := rand.Int(rand.Reader, maxRand)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	encrypted, zk, err := pk.Encrypt(rand1)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying first encryption ZKProof: %v", err)
		return
	}
	rand2, err := rand.Int(rand.Reader, maxRand)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	encrypted2, zk, err := pk.Encrypt(rand2)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying second encryption ZKProof: %v", err)
		return
	}
	randSum := new(big.Int).Add(rand1, rand2)

	encryptedSum, err := pk.Add(encrypted, encrypted2)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	decryptShares := make([]*tcpaillier.DecryptionShare, l)
	for i, share := range shares {
		decryptShare, err := share.DecryptProof(encryptedSum)
		if err != nil {
			t.Errorf("share %d is not able to decrypt partially the message: %v", share.Index, err)
			return
		}
		if err := decryptShare.Verify(pk); err != nil {
			t.Errorf("error verifying decryption ZKProof: %v", err)
			return
		}
		decryptShares[i] = decryptShare
	}
	decrypted, err := pk.CombineShares(decryptShares...)
	if err != nil {
		t.Errorf("cannot combine shares: %v", err)
		return
	}
	if decrypted.Cmp(randSum) != 0 {
		t.Errorf("messages are different:\nr1 =%s\nr2 =%s\ndec=%s\nexp=%s\nn  =%s\n", rand1, rand2, randSum, decrypted, pk.N)
		return
	}
}

func TestPubKey_RandMul(t *testing.T) {
	shares, pk, err := tcpaillier.NewKey(bitSize, s, l, k, rand.Reader)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	maxRand := new(big.Int).Rsh(pk.N, uint(pk.N.BitLen()/2))
	rand1, err := rand.Int(rand.Reader, maxRand)
	encrypted, zk, err := pk.Encrypt(rand1)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying first encryption ZKProof: %v", err)
		return
	}
	rand2, err := rand.Int(rand.Reader, maxRand)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	encryptedMul, zk, err := pk.Multiply(encrypted, rand2)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying multiplication ZKProof: %v", err)
		return
	}
	randSum := new(big.Int).Mul(rand1, rand2)
	randSum.Mod(randSum, pk.N)
	decryptShares := make([]*tcpaillier.DecryptionShare, l)
	for i, share := range shares {
		decryptShare, err := share.DecryptProof(encryptedMul)
		if err != nil {
			t.Errorf("share %d is not able to decrypt partially the message: %v", share.Index, err)
			return
		}
		if err := decryptShare.Verify(pk); err != nil {
			t.Errorf("error verifying decryption ZKProof: %v", err)
			return
		}
		decryptShares[i] = decryptShare
	}
	decrypted, err := pk.CombineShares(decryptShares...)
	if err != nil {
		t.Errorf("cannot combine shares: %v", err)
		return
	}
	if decrypted.Cmp(randSum) != 0 {
		t.Errorf("messages are different:\nr1 =%s\nr2 =%s\ndec=%s\nexp=%s\nn  =%s\n", rand1, rand2, randSum, decrypted, pk.N)
		return
	}
}

func TestPubKey_OverflowAdd(t *testing.T) {
	shares, pk, err := tcpaillier.NewKey(bitSize, s, l, k, rand.Reader)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	maxRand := new(big.Int)
	maxRand.SetBit(maxRand, pk.N.BitLen(), 1)
	encrypted, zk, err := pk.Encrypt(maxRand)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying first encryption ZKProof: %v", err)
		return
	}
	sum := new(big.Int).Add(maxRand, maxRand)
	sum.Mod(sum, pk.N)
	encryptedSum, err := pk.Add(encrypted, encrypted)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	decryptShares := make([]*tcpaillier.DecryptionShare, l)
	for i, share := range shares {
		decryptShare, err := share.DecryptProof(encryptedSum)
		if err != nil {
			t.Errorf("share %d is not able to decrypt partially the message: %v", share.Index, err)
			return
		}
		if err := decryptShare.Verify(pk); err != nil {
			t.Errorf("error verifying decryption ZKProof: %v", err)
			return
		}
		decryptShares[i] = decryptShare
	}
	decrypted, err := pk.CombineShares(decryptShares...)
	if err != nil {
		t.Errorf("cannot combine shares: %v", err)
		return
	}
	if decrypted.Cmp(sum) != 0 {
		t.Errorf("messages are different:\nmax =%s\ndec=%s\nexp=%s\nn  =%s\n", maxRand, sum, decrypted, pk.N)
		return
	}
}

func TestPubKey_OverflowMul(t *testing.T) {
	shares, pk, err := tcpaillier.NewKey(bitSize, s, l, k, rand.Reader)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	maxRand := new(big.Int)
	maxRand.SetBit(maxRand, pk.N.BitLen(), 1)
	encrypted, zk, err := pk.Encrypt(maxRand)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying first encryption ZKProof: %v", err)
		return
	}
	mul := new(big.Int).Mul(maxRand, maxRand)
	mul.Mod(mul, pk.N)
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying second encryption ZKProof: %v", err)
		return
	}
	encryptedMul, zk, err := pk.Multiply(encrypted, maxRand)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying multiplication ZKProof: %v", err)
		return
	}
	decryptShares := make([]*tcpaillier.DecryptionShare, l)
	for i, share := range shares {
		decryptShare, err := share.DecryptProof(encryptedMul)
		if err != nil {
			t.Errorf("share %d is not able to decrypt partially the message: %v", share.Index, err)
			return
		}
		if err := decryptShare.Verify(pk); err != nil {
			t.Errorf("error verifying decryption ZKProof: %v", err)
			return
		}
		decryptShares[i] = decryptShare
	}
	decrypted, err := pk.CombineShares(decryptShares...)
	if err != nil {
		t.Errorf("cannot combine shares: %v", err)
		return
	}
	if decrypted.Cmp(mul) != 0 {
		t.Errorf("messages are different:\nmax =%s\ndec=%s\nexp=%s\nn  =%s\n", maxRand, mul, decrypted, pk.N)
		return
	}
}

func TestPubKey_FixedAdd(t *testing.T) {
	shares, pk, err := tcpaillier.NewKey(bitSize, s, l, k, rand.Reader)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	maxRand := new(big.Int).Rsh(pk.N, 1)
	rand1, err := rand.Int(rand.Reader, maxRand)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	encrypted, zk, err := pk.EncryptFixed(rand1, big.NewInt(1))
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying first encryption ZKProof: %v", err)
		return
	}
	rand2, err := rand.Int(rand.Reader, maxRand)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	encrypted2, zk, err := pk.EncryptFixed(rand2, big.NewInt(1))
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying second encryption ZKProof: %v", err)
		return
	}

	encryptedSum, err := pk.Add(encrypted, encrypted2)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	encryptedMul, zkp, err := pk.Multiply(encryptedSum, twelve)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if err := zkp.Verify(pk); err != nil {
		t.Errorf("%v", err)
		return
	}

	randMul := new(big.Int).Add(rand1, rand2)
	randMul.Mul(randMul, twelve).Mod(randMul, pk.N)

	decryptShares := make([]*tcpaillier.DecryptionShare, l)
	for i, share := range shares {
		decryptShare, err := share.DecryptProof(encryptedMul)
		if err != nil {
			t.Errorf("share %d is not able to decrypt partially the message: %v", share.Index, err)
			return
		}
		if err := decryptShare.Verify(pk); err != nil {
			t.Errorf("error verifying decryption ZKProof: %v", err)
			return
		}
		decryptShares[i] = decryptShare
	}
	decrypted, err := pk.CombineShares(decryptShares...)
	if err != nil {
		t.Errorf("cannot combine shares: %v", err)
		return
	}
	if decrypted.Cmp(randMul) != 0 {
		t.Errorf("messages are different:\nr1 =%s\nr2 =%s\ndec=%s\nexp=%s\nn  =%s\n", rand1, rand2, randMul, decrypted, pk.N)
		return
	}
}

func ExamplePubKey_Add() {
	// First, we create the shares with the parameters provided.
	shares, pk, err := tcpaillier.NewKey(512, 1, 5, 3, rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}

	// Now we encrypt two values: 12 and 25
	encTwelve, zk, err := pk.Encrypt(big.NewInt(12))
	if err != nil {
		panic(err)
	}
	if err := zk.Verify(pk); err != nil {
		panic(err)
	}
	encTwentyFive, zk, err := pk.Encrypt(big.NewInt(25))
	if err != nil {
		panic(err)
	}

	// We sum them using Add
	thirtySevenSum, err := pk.Add(encTwelve, encTwentyFive)
	if err != nil {
		panic(err)
	}

	// We decrypt them with our shares
	decryptShares := make([]*tcpaillier.DecryptionShare, l)
	for i, share := range shares {
		decryptShare, err := share.DecryptProof(thirtySevenSum)
		if err != nil {
			panic(err)
		}
		if err := decryptShare.Verify(pk); err != nil {
			panic(err)
		}
		decryptShares[i] = decryptShare
	}

	// We combine the shares and get the decrypted and summed value
	decrypted, err := pk.CombineShares(decryptShares...)
	if err != nil {
		panic(err)
	}

	// It should be 37
	fmt.Printf("%s", decrypted)
	// Output: 37
}

func ExamplePubKey_Multiply() {
	// First, we create the shares with the parameters provided.
	shares, pk, err := tcpaillier.NewKey(512, 1, 5, 3, rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}

	// Now we encrypt two values: 12 and 25
	encTwelve, zk, err := pk.Encrypt(big.NewInt(12))
	if err != nil {
		panic(err)
	}
	if err := zk.Verify(pk); err != nil {
		panic(err)
	}

	// We multiply them
	thirtySevenSum, zkp, err := pk.Multiply(encTwelve, big.NewInt(25))
	if err != nil {
		panic(err)
	}

	if err := zkp.Verify(pk); err != nil {
		panic(err)
	}

	// We decrypt them with our shares
	decryptShares := make([]*tcpaillier.DecryptionShare, l)
	for i, share := range shares {
		decryptShare, err := share.DecryptProof(thirtySevenSum)
		if err != nil {
			panic(err)
		}
		if err := decryptShare.Verify(pk); err != nil {
			panic(err)
		}
		decryptShares[i] = decryptShare
	}

	// We combine the shares and get the decrypted value
	decrypted, err := pk.CombineShares(decryptShares...)
	if err != nil {
		panic(err)
	}

	// It should be 300
	fmt.Printf("%s", decrypted)
	// Output: 300
}
