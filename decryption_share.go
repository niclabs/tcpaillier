package tcpaillier

import (
	"math/big"
)

// DecryptionShare represents a partial decryption of a value
// and the ZKProof of that decryption. It complies with ZKProof
// interface.
type DecryptionShare struct {
	Index       uint8
	Ci          *big.Int
}
