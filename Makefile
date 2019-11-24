# I'm sure there is better way. But I would need to find it first
MK_FILE_PATH = $(lastword $(MAKEFILE_LIST))
PRJ_DIR      = $(abspath $(dir $(MK_FILE_PATH)))
GO           ?= go
VENDOR_DIR   = tls_vendor
OPTS         ?= -v
NOASM        ?=
TEST_PATH    ?= ./...
GOCACHE      ?= off
BENCH_OPTS   ?= -v -bench=. -run="^_" -benchmem
TEST_PATH    ?= ./...
DBG 		 = 1
OPTS_ENV	 =

ifeq ($(NOASM),1)
	OPTS+=$(OPTS_TAGS)
endif

ifeq ($(PPROF),1)
	BENCH_OPTS+= -cpuprofile=cpu.out -memprofile=mem0.out
endif

ifeq ($(DBG),1)
	DBG_FLAGS+= #-m 	# escape analysis
	DBG_FLAGS+= -l	# no inline
	DBG_FLAGS+= -N	# debug symbols
	#OPTS+=-gcflags=all="$(DBG_FLAGS)"
	OPTS+=-gcflags "$(DBG_FLAGS)"
	OPTS_ENV+= GOTRACEBACK=crash	# enable core dumps
endif

test: 
	$(OPTS_ENV) $(GO) test $(OPTS) $(TEST_PATH)

test_csidh: clean make_dirs $(addprefix prep-,$(TARGETS))
	cd $(GOPATH_LOCAL); $(OPTS_ENV) GOPATH=$(GOPATH_LOCAL) go test $(OPTS) github.com/henrydcase/nobs/dh/csidh

test_csidh_bin: clean make_dirs $(addprefix prep-,$(TARGETS))
	cd $(GOPATH_LOCAL); $(OPTS_ENV) GOPATH=$(GOPATH_LOCAL) go test -c $(OPTS) github.com/henrydcase/nobs/dh/csidh

cover:
	$(GO) test \
		-coverprofile=coverage.txt -covermode=atomic $(OPTS) $(TEST_PATH)

bench:
	$(GO) test $(BENCH_OPTS) $(TEST_PATH)

bench_csidh: clean $(addprefix prep-,$(TARGETS))
	cd $(GOPATH_LOCAL); GOCACHE=$(GOCACHE) GOPATH=$(GOPATH_LOCAL) $(GO) test \
		$(BENCH_OPTS) github.com/henrydcase/nobs/dh/csidh
		
clean:
	rm -rf $(VENDOR_DIR)
	rm -rf coverage.txt

vendor-sidh-for-tls: clean
	mkdir -p $(VENDOR_DIR)/github_com/henrydcase/nobs/
	rsync -a . $(VENDOR_DIR)/github_com/henrydcase/nobs/ --exclude=$(VENDOR_DIR) --exclude=.git --exclude=.travis.yml --exclude=README.md
	find $(VENDOR_DIR) -type f -print0 -name "*.go" | xargs -0 sed -i 's/github\.com/github_com/g'

pprof-cpu:
	$(GO) tool pprof cpu.out

pprof-mem:
	$(GO) tool pprof mem0.out
