package tcpaillier

import (
	"math/big"
)

// DecryptionShare represents A partial decryption of A value
// and the ZKProof of that decryption. It complies with ZKProof
// interface.
type DecryptionShare struct {
	Index       uint8
	Ci          *big.Int
}
