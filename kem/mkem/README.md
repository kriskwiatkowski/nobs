# mKEM for cSIDH/p512

Implementation of multi-KEM for SIKE and multi-PKE for cSIDH.

## Implementation

The implementation is done in Go. Compilation requires go 1.12 or newer to compile with ``GO111MODULE=on``. Implementation is based on cSIDH and SIDH from NOBS NOBS [library](github.com/henrydcase/nobs).

## Running and benchmarking

To run all benchmarks use following command
```
make run
```

It is possible to run only subset of benchmarks. The command ``make run-cycles`` will calculate CPU cycles for encryption/encapsulation to N users. The command ``make run-ns`` will produce results in nanoseconds.


### Results
Benchmarks has been run on i7-8665U (Whiskey Lake) @ 1.90GHz

* CPU cycle count

```
Test name:                | Cycle count:
--------------------------|--------------
bench_SIKEp434_KEM        | 1720710678
bench_SIKEp503_KEM        | 2411750152
bench_SIKEp751_KEM        | 7225841287
bench_SIKEp434_mKEM       | 783353356
bench_SIKEp503_mKEM       | 1100170053
bench_SIKEp751_mKEM       | 3304027422
bench_CSIDH_PKE           | 38200232832
bench_CSIDH_mPKE          | 19203013803
```

* Time in ns

```
./mkem.test -test.run="notest" -test.bench=BenchmarkMultiEncaps -test.cpu=1

BenchmarkMultiEncaps_100keys/P-434         	       3	 357838360 ns/op
BenchmarkMultiEncaps_100keys/P-503         	       2	 503749852 ns/op
BenchmarkMultiEncaps_100keys/P-751         	       1	1514791804 ns/op


./mkem.test -test.run="notest" -test.bench=BenchmarkEncaps -test.cpu=1
BenchmarkEncaps/P-434         	     151	   7888643 ns/op
BenchmarkEncaps/P-503         	     100	  11150691 ns/op
BenchmarkEncaps/P-751         	      36	  34494941 ns/op

./mkem.test -test.run="notest" -test.bench=BenchmarkEncrypt_CSIDH_p512 -test.cpu=1
BenchmarkEncrypt_CSIDH_p512 	       7	 185828599 ns/op

./mkem.test -test.run="notest" -test.bench=BenchmarkMultiEncrypt_CSIDH_100keys -test.cpu=1
BenchmarkMultiEncrypt_CSIDH_100keys 	       1	1025902914 ns/op
```

### Paper
Details of this construction has been presented at (ASIACRYPT 2020)[https://www.youtube.com/watch?v=0ijRmXt01Ww] and are described in the (ia.cr/2020/1107)[ia.cr/2020/1107]
