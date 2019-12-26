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
var thirtySeven = big.NewInt(37)
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
	encrypted, zk, err := pk.Encrypt(twelve.Bytes())
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying encryption ZKProof: %v", err)
		//return
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
	bigDec := new(big.Int).SetBytes(decrypted)
	if bigDec.Cmp(twelve) != 0 {
		t.Errorf("messages are different. Decrypted is %s and twelve was %s.", decrypted, twelve)
		return
	}
}

func TestPubKey_EncryptSum(t *testing.T) {
	shares, pk, err := tcpaillier.NewKey(bitSize, s, l, k, rand.Reader)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	encrypted, zk, err := pk.Encrypt(twelve.Bytes())
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying first encryption ZKProof: %v", err)
		//return
	}
	encrypted2, zk, err := pk.Encrypt(twentyFive.Bytes())
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying second encryption ZKProof: %v", err)
		//return
	}

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
	bigDec := new(big.Int).SetBytes(decrypted)
	if bigDec.Cmp(thirtySeven) != 0 {
		t.Errorf("messages are different. Decrypted is %s and twelve was %s.", decrypted, twelve)
		return
	}
}

func TestPubKey_EncryptMul(t *testing.T) {
	shares, pk, err := tcpaillier.NewKey(bitSize, s, l, k, rand.Reader)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	encrypted, zk, err := pk.Encrypt(twelve.Bytes())
	if err != nil {
		t.Errorf("error encrypting twelve: %v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying first encryption ZKProof: %v", err)
		//return
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
	bigDec := new(big.Int).SetBytes(decrypted)
	if bigDec.Cmp(threeHundred) != 0 {
		t.Errorf("messages are different. Decrypted is %s and twelve was %s.", decrypted, twelve)
		return
	}
}

func ExampleAdd() {
	// First, we create the shares with the parameters provided.
	shares, pk, err := tcpaillier.NewKey(512, 1, 5, 3, rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}

	// Now we encrypt two values: 12 and 25
	encTwelve, zk, err := pk.Encrypt(big.NewInt(12).Bytes())
	if err != nil {
		panic(err)
	}
	if err := zk.Verify(pk); err != nil {
		panic(err)
	}
	encTwentyFive, zk, err := pk.Encrypt(big.NewInt(25).Bytes())
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
	bigDec := new(big.Int).SetBytes(decrypted)
	fmt.Printf("%s", bigDec)
	// Output: 37
}

func ExampleMultiply() {
	// First, we create the shares with the parameters provided.
	shares, pk, err := tcpaillier.NewKey(512, 1, 5, 3, rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}

	// Now we encrypt two values: 12 and 25
	encTwelve, zk, err := pk.Encrypt(big.NewInt(12).Bytes())
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
	bigDec := new(big.Int).SetBytes(decrypted)
	fmt.Printf("%s", bigDec)
	// Output: 300
}
