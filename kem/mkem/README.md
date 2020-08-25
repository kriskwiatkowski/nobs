# mKEM for cSIDH/p512

Implementation of multi-KEM for done on top of cSIDH implementation from NOBS [library](github.com/henrydcase/nobs/dh/csidh).

## Implementation choices

TODO:
- choice of H
- message length
- golang

## Running and benchmarking

To run benchmark tests golang 1.10 is required to be installed. Following command can be used to run the benchmark tests

```
go test -v -bench=. -run="notest"
```

Results on SkyLake CPU:

```
> go test -v -bench=. -run="notest" -benchmem
goos: linux
goarch: amd64
pkg: github.com/henrydcase/nobs/kem/mkem
BenchmarkCSIDH_Enc_10keys
BenchmarkCSIDH_Enc_10keys-8     	       2	 761984058 ns/op	    6720 B/op	      31 allocs/op
BenchmarkCSIDH_mEnc_10keys
BenchmarkCSIDH_mEnc_10keys-8    	       3	 436651776 ns/op	    1426 B/op	       5 allocs/op
BenchmarkCSIDH_Enc_100keys
BenchmarkCSIDH_Enc_100keys-8    	       1	7883272803 ns/op	   67968 B/op	     301 allocs/op
BenchmarkCSIDH_mEnc_100keys
BenchmarkCSIDH_mEnc_100keys-8   	       1	3832287289 ns/op	    7312 B/op	       5 allocs/op
PASS
ok  	github.com/henrydcase/nobs/kem/mkem	20.691s

```
