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

var msg = big.NewInt(12)
var msg2 = big.NewInt(25)
var resulSum = big.NewInt(37)
var resulMul = big.NewInt(300)

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
	encrypted, zk, err := pk.Encrypt(msg.Bytes())
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
	if bigDec.Cmp(msg) != 0 {
		t.Errorf("messages are different. Decrypted is %s and msg was %s.", decrypted, msg)
		return
	}
}

func TestPubKey_EncryptSum(t *testing.T) {
	shares, pk, err := tcpaillier.NewKey(bitSize, s, l, k, rand.Reader)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	encrypted, zk, err := pk.Encrypt(msg.Bytes())
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying first encryption ZKProof: %v", err)
		//return
	}
	encrypted2, zk, err := pk.Encrypt(msg2.Bytes())
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
	if bigDec.Cmp(resulSum) != 0 {
		t.Errorf("messages are different. Decrypted is %s and msg was %s.", decrypted, msg)
		return
	}
}

func TestPubKey_EncryptMul(t *testing.T) {
	shares, pk, err := tcpaillier.NewKey(bitSize, s, l, k, rand.Reader)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	encrypted, zk, err := pk.Encrypt(msg.Bytes())
	if err != nil {
		t.Errorf("error encrypting msg: %v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying first encryption ZKProof: %v", err)
		//return
	}

	encryptedMul, proof, err := pk.Multiply(encrypted, msg2)
	if err != nil {
		t.Errorf("Error multiplying msg for constant %s: %v", msg2, err)
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
	if bigDec.Cmp(resulMul) != 0 {
		t.Errorf("messages are different. Decrypted is %s and msg was %s.", decrypted, msg)
		return
	}
}

func Example() {
	shares, _, err := tcpaillier.NewKey(bitSize, s, l, k, rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}

	if len(shares) < l {
		panic(fmt.Errorf("length of shares is %d instead of %d", len(shares), l))
	}
}
