module github.com/james-antill/uhash/cmd/uhash

replace github.com/james-antill/uhash => ../../

go 1.21.0

require (
	github.com/cespare/xxhash v1.1.0
	github.com/dgryski/dgohash v0.0.0-20181015193854-bc94635621ad
	github.com/james-antill/uhash v0.0.0-00010101000000-000000000000
	github.com/twmb/murmur3 v1.1.8
	github.com/zeebo/blake3 v0.2.4
	golang.org/x/crypto v0.33.0
)

require (
	github.com/klauspost/cpuid/v2 v2.0.12 // indirect
	golang.org/x/sys v0.30.0 // indirect
)
