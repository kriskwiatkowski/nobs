test:
	go test -v ./...

vendor-sidh-for-tls:
	rm -rf tls_vendor
	mkdir -p tls_vendor/github_com/henrydcase/nobs/
	rsync -a . tls_vendor/github_com/henrydcase/nobs/ --exclude=tls_vendor --exclude=.git --exclude=.travis.yml --exclude=README.md
	find tls_vendor -type f -print0 -name "*.go" | xargs -0 sed -i 's/github\.com/github_com/g'