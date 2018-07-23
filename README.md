# nobs-j-crypto

Crypto primitives implementation in Go.

## Implemented primitives
* dh/
    - SIDH
* hash/
    - cSHAKE (sha3 coppied from "golang.org/x/crypto")
    - SM3
* rand/
    - CTR_DRBG with AES256 (NIST SP800-90A)
* kem/
    - SIKE: version 3 (as per paper on sike.org)
    
## Testing
```
make test
```