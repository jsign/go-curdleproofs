# Curdleproofs
A Go implementation of [Curdleproofs](https://github.com/asn-d6/curdleproofs/blob/main/doc/curdleproofs.pdf), a zero-knowledge shuffle argument inspired by BG12.

It's the backbone of [Whisk](https://ethresear.ch/t/whisk-a-practical-shuffle-based-ssle-protocol-for-ethereum/11763) a practical shuffle-based secret single leader election (SSLE) protocol for Ethereum.

## Status

This library is in feature parity with the Rust reference implementation. 
Also, is not yet audited, so be careful if you're considering using it in production. 

## Benchmarks

The following are benchmarks for 64, 128 and 256 elements (including blinders):
```
goos: linux
goarch: amd64
pkg: github.com/jsign/curdleproofs
cpu: AMD Ryzen 7 3800XT 8-Core Processor            
BenchmarkProver/shuffled_elements=60-16                       12          94740346 ns/op
BenchmarkProver/shuffled_elements=124-16                       7         150115008 ns/op
BenchmarkProver/shuffled_elements=252-16                       5         238523279 ns/op
BenchmarkProver/shuffled_elements=508-16                       3         404879574 ns/op
BenchmarkVerifier/shuffled_elements=60-16                    115          10175408 ns/op
BenchmarkVerifier/shuffled_elements=124-16                    99          11870850 ns/op
BenchmarkVerifier/shuffled_elements=252-16                    72          15094033 ns/op
```

The implementation has the optimizations mentioned in the paper and some extra minor ones. No extra effort was made to optimize further (i.e: there might be other trivial or advanced cryptography or engineering to apply).

## License

MIT