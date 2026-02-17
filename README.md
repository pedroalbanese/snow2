# snow2
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/snow2/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/snow2?status.png)](http://godoc.org/github.com/pedroalbanese/snow2)
[![Go Report Card](https://goreportcard.com/badge/github.com/pedroalbanese/snow2)](https://goreportcard.com/report/github.com/pedroalbanese/snow2)
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.18672514-blue.svg)](https://doi.org/10.5281/zenodo.18672514)

#### SNOW 2.0 Stream Cipher in Pure Go, Python, and PHP

SNOW 2.0 is a synchronous stream cipher designed for high-speed software encryption. It combines a Linear Feedback Shift Register (LFSR) over the finite field GF(2¹⁶) with a Finite State Machine (FSM) to generate a secure pseudorandom keystream. The cipher supports key lengths of 128 or 256 bits and produces output that can be XORed with plaintext for encryption, providing strong resistance against known cryptanalytic attacks while remaining efficient for modern processors. SNOW 2.0 is standardized in ISO/IEC 18033-4:2011.

## License

This project is licensed under the ISC License.

#### Copyright (c) 2020-2026 Pedro F. Albanese - ALBANESE Research Lab.  
Todos os direitos de propriedade intelectual sobre este software pertencem ao autor, Pedro F. Albanese. Vide Lei 9.610/98, Art. 7º, inciso XII.
