# Curdleproofs
A Go implementation of [Curdleproofs](https://github.com/asn-d6/curdleproofs/blob/main/doc/curdleproofs.pdf), a zero-knowledge shuffle argument inspired by BG12.

It's the backbone of [Whisk](https://ethresear.ch/t/whisk-a-practical-shuffle-based-ssle-protocol-for-ethereum/11763) a practical shuffle-based secret single leader election (SSLE) protocol for Ethereum.

## Status

This library is in feature parity with the Rust reference implementation. The Whisk interface is not implemented yet since it's still in flux, but it will be implemented soon.

This library is not yet audited, and should not be used in production. Here be dragons!

## Benchmarks

Benchmarks for Curdleproofs and their internal arguments will be implemented soon.

Despite implementing all the performance optimizations mentioned in the paper, there might be other optimizations that can/will be done.

## License

MIT