package tcpaillier

import "math/big"


type KeyShare struct {
	*PubKey
	Index uint8
	Si    *big.Int
}
