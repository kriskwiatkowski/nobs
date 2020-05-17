all: run-cycles

GO=go
PARAMS=

test:
	$(GO) test -run=.

ns:
	$(GO) test -c

cycles:
	$(GO) build cmd/bench.go

run-ns: ns
	./mkem.test -test.run="notest" -test.bench=BenchmarkMultiEncaps -test.cpu=1 ${PARAMS}
	./mkem.test -test.run="notest" -test.bench=BenchmarkEncaps -test.cpu=1 ${PARAMS}
	./mkem.test -test.run="notest" -test.bench=BenchmarkEncrypt_CSIDH_p512 -test.cpu=1 ${PARAMS}
	./mkem.test -test.run="notest" -test.bench=BenchmarkMultiEncrypt_CSIDH_100keys -test.cpu=1 ${PARAMS}

run-cycles: cycles
	./bench

run: cycles ns run-cycles run-ns

.PHONY: ns test run-cycles run-ns run
