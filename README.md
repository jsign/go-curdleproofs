# Curdleproofs
A Go implementation of [Curdleproofs](https://github.com/asn-d6/curdleproofs/blob/main/doc/curdleproofs.pdf), a zero-knowledge shuffle argument inspired by BG12.

It's the backbone of [Whisk](https://ethresear.ch/t/whisk-a-practical-shuffle-based-ssle-protocol-for-ethereum/11763) a practical shuffle-based secret single leader election (SSLE) protocol for Ethereum.

## Status

This library is in feature parity with the Rust reference implementation. 

This library is not yet audited, and should not be used in production. Here be dragons!

## Benchmarks

The following are benchmarks for 64, 128 and 256 elements (including blinders):
```
goos: linux
goarch: amd64
pkg: github.com/jsign/curdleproofs
cpu: AMD Ryzen 7 3800XT 8-Core Processor            
BenchmarkProver/shuffled_elements=60-16                       12          96241397 ns/op
BenchmarkProver/shuffled_elements=124-16                       7         147237624 ns/op
BenchmarkProver/shuffled_elements=252-16                       5         233925449 ns/op
BenchmarkVerifier/shuffled_elements=60-16                    115          10346387 ns/op
BenchmarkVerifier/shuffled_elements=124-16                   102          11821016 ns/op
BenchmarkVerifier/shuffled_elements=252-16                    72          14792873 ns/op
```

The implementation has the optimizations mentioned in the paper and some extra minor ones. No extra effort was made to optimize further (i.e: there might be other trivial or advanced cryptography or engineering to apply).

## License

MIT