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
const s = 1

const bitSize = 512

var msg = big.NewInt(12)

func TestGenKeyShares(t *testing.T) {
	shares, err := tcpaillier.GenKeyShares(bitSize, s, l, k, rand.Reader)
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

func TestPubKey_EncryptWithProof(t *testing.T) {
	shares, err := tcpaillier.GenKeyShares(bitSize, s, l, k, rand.Reader)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	pk := shares[0].PubKey
	encrypted, zk, err := pk.EncryptWithProof(msg.Bytes())
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if err := zk.Verify(pk); err != nil {
		t.Errorf("error verifying ZKProof: %v", err)
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
			//return
		}
		decryptShares[i] = decryptShare
	}
	decrypted, err := pk.CombineShares(decryptShares...)
	if err != nil {
		t.Errorf("cannot combine shares: %v", err)
		return
	}
	if new(big.Int).SetBytes(decrypted).Cmp(msg) == 0 {
		t.Errorf("messages are different. Decrypted is %s and msg was %s.", decrypted, msg)
	}
}

func Example() {
	shares, err := tcpaillier.GenKeyShares(bitSize, s, l, k, rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}

	if len(shares) < l {
		panic(fmt.Errorf("length of shares is %d instead of %d", len(shares), l))
	}
}
