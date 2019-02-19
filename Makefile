# I'm sure there is better way. But I would need to find it first
MK_FILE_PATH = $(lastword $(MAKEFILE_LIST))
PRJ_DIR      = $(abspath $(dir $(MK_FILE_PATH)))
GOPATH_LOCAL = $(PRJ_DIR)/build/
GOPATH_DIR   = src/github.com/henrydcase/nobs
VENDOR_DIR   = tls_vendor
OPTS         ?= -v
NOASM		 ?=
ETC_DIR      = $(PRJ_DIR)/etc
GO           ?= go
BENCH_OPTS   ?= -bench=. -run="^_"
V            ?= 0
GOCACHE      ?= off
GOARCH       ?=
ETC_DIR      = $(PRJ_DIR)/etc
BENCH_NAME	 = BenchmarkXMul
DBG 		 = 1
OPTS_ENV	 =
ifeq ($(NOASM),1)
	OPTS+=$(OPTS_TAGS)
endif

ifeq ($(DBG),1)
	DBG_FLAGS+= #-m 	# escape analysis
	DBG_FLAGS+= -l	# no inline
	DBG_FLAGS+= -N	# debug symbols
	#OPTS+=-gcflags=all="$(DBG_FLAGS)"
	OPTS+=-gcflags "$(DBG_FLAGS)"
	OPTS_ENV+= GOTRACEBACK=crash	# enable core dumps
endif

TARGETS= \
	dh   \
	drbg \
	ec \
	hash \
	kem \
	utils

prep-%:
	mkdir -p $(GOPATH_LOCAL)/$(GOPATH_DIR)
	cp -rf $* $(GOPATH_LOCAL)/$(GOPATH_DIR)/$*

make_dirs:
	mkdir -p $(GOPATH_LOCAL)/$(GOPATH_DIR)
	cp -rf etc $(GOPATH_LOCAL)/$(GOPATH_DIR)

test: clean make_dirs $(addprefix prep-,$(TARGETS))
	cd $(GOPATH_LOCAL); $(OPTS_ENV) GOPATH=$(GOPATH_LOCAL) go test $(OPTS) ./...

build: clean make_dirs $(addprefix prep-,$(TARGETS))
	cd $(GOPATH_LOCAL); $(OPTS_ENV) GOPATH=$(GOPATH_LOCAL) go build $(OPTS) ./...

cover:
	cd $(GOPATH_LOCAL); $(OPTS_ENV) GOPATH=$(GOPATH_LOCAL) go test \
		-race -coverprofile=coverage_$(NOASM).txt -covermode=atomic $(OPTS) ./...
	cat $(GOPATH_LOCAL)/coverage_$(NOASM).txt >> coverage.txt

clean:
	rm -rf $(GOPATH_LOCAL)
	rm -rf $(VENDOR_DIR)

vendor-sidh-for-tls: clean
	mkdir -p $(VENDOR_DIR)/github_com/henrydcase/nobs/
	rsync -a . $(VENDOR_DIR)/github_com/henrydcase/nobs/ --exclude=$(VENDOR_DIR) --exclude=.git --exclude=.travis.yml --exclude=README.md
	find $(VENDOR_DIR) -type f -print0 -name "*.go" | xargs -0 sed -i 's/github\.com/github_com/g'

bench: clean $(addprefix prep-,$(TARGETS))
	cd $(GOPATH_LOCAL); $(OPTS_ENV) GOCACHE=$(GOCACHE) GOPATH=$(GOPATH_LOCAL) GOMAXPROCS=1 $(GO) test \
		$(BENCH_OPTS) ./...

bench_csidh: clean make_dirs $(addprefix prep-,$(TARGETS))
	cd $(GOPATH_LOCAL); $(OPTS_ENV) GOCACHE=$(GOCACHE) GOPATH=$(GOPATH_LOCAL) GOMAXPROCS=1 $(GO) test \
		$(OPTS) -run="^_" -bench=$(BENCH_NAME) -memprofile mem.prof -benchmem github.com/henrydcase/nobs/dh/csidh

test_drbg: clean make_dirs $(addprefix prep-,$(TARGETS))
	cd $(GOPATH_LOCAL); $(OPTS_ENV) GOCACHE=$(GOCACHE) GOPATH=$(GOPATH_LOCAL) GOMAXPROCS=1 $(GO) test \
		$(OPTS) -c -run=. github.com/henrydcase/nobs/drbg

bench_drbg: clean make_dirs $(addprefix prep-,$(TARGETS))
	cd $(GOPATH_LOCAL); $(OPTS_ENV) GOCACHE=$(GOCACHE) GOPATH=$(GOPATH_LOCAL) GOMAXPROCS=1 $(GO) test \
		$(OPTS) -run="XXX" -bench=. -benchmem -memprofile=drbg_prof github.com/henrydcase/nobs/drbg
