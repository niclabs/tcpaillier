# Paillier Threshold Encryption Scheme Implementation

[![Go Report Card](https://goreportcard.com/badge/github.com/niclabs/tcpaillier)](https://goreportcard.com/report/github.com/niclabs/tcpaillier)
[![Build Status](https://travis-ci.org/niclabs/tcpaillier.svg?branch=master)](https://travis-ci.org/niclabs/tcpaillier)
[![GoDoc](https://godoc.org/github.com/niclabs/tcpaillier?status.svg)](https://godoc.org/github.com/niclabs/tcpaillier)


This code is based on the implementation of Paillier Threshold Encryption Scheme from 
[UTDallas](http://cs.utdallas.edu/dspl/cgi-bin/pailliertoolbox/index.php), and both implementations are based on the
paper from Ivan Damgård et al. [A Generalization of Paillier's Public Key System with Applications to Electronic Voting](https://people.csail.mit.edu/rivest/voting/papers/DamgardJurikNielsen-AGeneralizationOfPailliersPublicKeySystemWithApplicationsToElectronicVoting.pdf).

# Requirements

Due to Golang extensive standard library, this implementation does not have external requirements (obviously aside of Golang, version 1.13 or above).

# Using the Library

To use the library with a module-enabled go project, you must write the following line on a terminal on the root file of the project.

```bash
go get https://github.com/niclabs/tcpaillier
```

# Testing

To run the tests you just need to use go test:

```bash
go test github.com/niclabs/tcpaillier
```
