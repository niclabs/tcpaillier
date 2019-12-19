# Threshold Paillier Encryption Scheme Implementation

[![GoDoc](https://godoc.org/github.com/niclabs/tcpaillier?status.svg)](https://godoc.org/github.com/niclabs/tcpaillier)
[![Go Report Card](https://goreportcard.com/badge/github.com/niclabs/tcpaillier)](https://goreportcard.com/report/github.com/niclabs/tcpaillier)


This code is based on the implementation of Threshold Paillier Encryption Scheme from 
[UTDallas](http://cs.utdallas.edu/dspl/cgi-bin/pailliertoolbox/index.php).

That implementation is based on the
paper from Ivan Damgård et al. [A Generalization of Paillier's Public Key System with Applications to Electronic Voting](https://people.csail.mit.edu/rivest/voting/papers/DamgardJurikNielsen-AGeneralizationOfPailliersPublicKeySystemWithApplicationsToElectronicVoting.pdf)

Requirements

Due to Golang extensive standard library, this implementation does not have external requirements (obviously aside of Golang, version 1.12 or above).
Installing

go get https://github.com/niclabs/tcpaillier

To run the tests you just need to use go test:

go test