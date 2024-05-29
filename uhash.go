package uhash

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
)

type Kind int

type Hash interface {
	hash.Hash

	// Name returns the default Name of the hash
	Kind() Kind
}

type HashFactory interface {
	// New creates a new instance of a hash
	New() hash.Hash

	// Size returns the number of bytes Sum will return.
	Size() int
}

type uhash struct {
	hash HashFactory
	kind Kind
	name string
}

func (u uhash) Kind() Kind {
	return u.kind
}
func (u uhash) Name() string {
	return u.name
}

func (u uhash) New() hash.Hash {
	return u.hash.New()
}
func (u uhash) Size() int {
	return u.hash.Size()
}

func String(u Hash) string {
	var resbuf [64]byte
	var res []byte = resbuf[:]
	if u.Size() > len(resbuf) {
		res = nil
	}

	return fmt.Sprintf("%s:%x", u.Kind().Name(), u.Sum(res))
}

type unknown struct {
}

func (u unknown) New() hash.Hash {
	return devnull{}
}
func (u unknown) Size() int {
	return 0
}
func (u unknown) BlockSize() int {
	return 0
}

var ErrNotFound = errors.New("Hash was not found")
var ErrAlreadyExists = errors.New("Hash already exists")

var kind2hash = []uhash{{unknown{}, 0, "Unknown"}}
var name2kind = map[string]Kind{}

func (k Kind) Hash() HashFactory {
	if k <= 0 || k > Kind(len(kind2hash)-1) {
		k = 0
	}

	return kind2hash[k].hash
}

func (k Kind) Name() string {
	if k <= 0 {
		return fmt.Sprintf("%s: %d", kind2hash[0].name, int(k))
	}

	if k > Kind(len(kind2hash)-1) {
		return fmt.Sprintf("%s: %d", kind2hash[0].name, int(k))
	}

	return kind2hash[k-1].name
}

func (k Kind) New() hash.Hash {
	return k.Hash().New()
}
func (k Kind) Size() int {
	return k.Hash().Size()
}

func (k Kind) String() string {
	return k.Name()
}

func (k Kind) AddAlias(alias string) (bool, error) {
	if k == 0 {
		return false, fmt.Errorf("Hash %s: %w", alias, ErrNotFound)
	}
	if _, ok := name2kind[alias]; ok {
		return false, fmt.Errorf("Hash %s: %w", alias, ErrAlreadyExists)
	}

	name2kind[alias] = k
	return true, nil
}

type Checksum []byte

func (c Checksum) String() string {
	return hex.EncodeToString(c)
}
func (c Checksum) Hex() string {
	return hex.EncodeToString(c)
}

func (c Checksum) Equal(c2 Checksum) bool {
	return bytes.Equal(c, c2)
}
func (c Checksum) EqualBytes(b []byte) bool {
	return bytes.Equal(c, b)
}
func (c Checksum) EqualString(s string) bool {
	if false && len(c) != (2*len(s)) { // Minor speedup
		return false
	}

	// Better way to do this?
	return c.String() == s
}

// Result is a holder for the result of a checksum
type Result struct {
	Kind Kind
	Data Checksum
}

func Add(name string, hi HashFactory) (Kind, error) {
	if _, ok := name2kind[name]; ok {
		return 0, fmt.Errorf("Hash %s: %w", name, ErrAlreadyExists)
	}

	h := uhash{hi, Kind(len(kind2hash)), name}
	kind2hash = append(kind2hash, h)
	name2kind[name] = h.kind

	return h.kind, nil
}

func Lookup(csum string) (Kind, error) {
	k, ok := name2kind[csum]
	if !ok {
		return 0, fmt.Errorf("Hash %s: %w", csum, ErrNotFound)
	}

	return k, nil
}

func New(name string) (Kind, hash.Hash, error) {
	k, err := Lookup(name)
	if err != nil {
		return 0, nil, err
	}

	return k, k.New(), nil
}

func init() {
	// import golang.org/x/crypto/md4
	if crypto.MD4.Available() {
		kind, _ := Add("MD4", crypto.MD4)
		kind.AddAlias("md4")
	}

	// import crypto/md5
	if crypto.MD5.Available() {
		kind, _ := Add("MD5", crypto.MD5)
		kind.AddAlias("md5")
	}

	// import crypto/sha1
	if crypto.SHA1.Available() {
		kind, _ := Add("SHA1", crypto.SHA1)
		kind.AddAlias("sha1")
		kind.AddAlias("SHA-1")
		kind.AddAlias("sha-1")
		//		kind.AddAlias("sha") // ?
	}

	// import crypto/sha256
	if crypto.SHA224.Available() {
		kind, _ := Add("SHA224", crypto.SHA224)
		kind.AddAlias("sha224")
		kind.AddAlias("SHA-224")
		kind.AddAlias("sha-224")
		kind.AddAlias("SHA2-224")
		kind.AddAlias("sha2-224")
	}

	// import crypto/sha256
	if crypto.SHA256.Available() {
		kind, _ := Add("SHA256", crypto.SHA256)
		kind.AddAlias("sha256")
		kind.AddAlias("SHA-256")
		kind.AddAlias("sha-256")

		kind.AddAlias("SHA2-256")
		kind.AddAlias("sha2-256")
		kind.AddAlias("SHA-2-256")
		kind.AddAlias("sha-2-256")
	}

	// import crypto/sha512
	if crypto.SHA384.Available() {
		kind, _ := Add("SHA384", crypto.SHA384)
		kind.AddAlias("sha384")
		kind.AddAlias("SHA-384")
		kind.AddAlias("sha-384")

		kind.AddAlias("SHA2-384")
		kind.AddAlias("sha2-384")
		kind.AddAlias("SHA-2-384")
		kind.AddAlias("sha-2-384")
	}

	// import crypto/sha512
	if crypto.SHA512.Available() {
		kind, _ := Add("SHA512", crypto.SHA512)
		kind.AddAlias("sha512")
		kind.AddAlias("SHA-512")
		kind.AddAlias("sha-512")

		kind.AddAlias("SHA2-512")
		kind.AddAlias("sha2-512")
		kind.AddAlias("SHA-2-512")
		kind.AddAlias("sha-2-512")
	}

	// crypto.MD5SHA1 // no implementation; MD5+SHA1 used for TLS RSA

	// import golang.org/x/crypto/ripemd160
	if crypto.RIPEMD160.Available() {
		kind, _ := Add("RIPEMD160", crypto.RIPEMD160)
		kind.AddAlias("ripemd160")
	}

	// import golang.org/x/crypto/sha3
	if crypto.SHA3_224.Available() {
		kind, _ := Add("SHA3-224", crypto.SHA3_224)
		kind.AddAlias("sha3-224")
		kind.AddAlias("SHA3_224")
		kind.AddAlias("sha3_224")

		kind.AddAlias("SHA-3_224")
		kind.AddAlias("sha-3_224")
		kind.AddAlias("SHA-3-224")
		kind.AddAlias("sha-3-224")
	}

	// import golang.org/x/crypto/sha3
	if crypto.SHA3_256.Available() {
		kind, _ := Add("SHA3-256", crypto.SHA3_256)
		kind.AddAlias("sha3-256")
		kind.AddAlias("SHA3_256")
		kind.AddAlias("sha3_256")

		kind.AddAlias("SHA-3_256")
		kind.AddAlias("sha-3_256")
		kind.AddAlias("SHA-3-256")
		kind.AddAlias("sha-3-256")
	}

	// import golang.org/x/crypto/sha3
	if crypto.SHA3_384.Available() {
		kind, _ := Add("SHA3-384", crypto.SHA3_384)
		kind.AddAlias("sha3-384")
		kind.AddAlias("SHA3_384")
		kind.AddAlias("sha3_384")

		kind.AddAlias("SHA-3_384")
		kind.AddAlias("sha-3_384")
		kind.AddAlias("SHA-3-384")
		kind.AddAlias("sha-3-384")
	}

	// import golang.org/x/crypto/sha3
	if crypto.SHA3_512.Available() {
		kind, _ := Add("SHA3-512", crypto.SHA3_512)
		kind.AddAlias("sha3-512")
		kind.AddAlias("SHA3_512")
		kind.AddAlias("sha3_512")

		kind.AddAlias("SHA-3_512")
		kind.AddAlias("sha-3_512")
		kind.AddAlias("SHA-3-512")
		kind.AddAlias("sha-3-512")
	}

	// import crypto/sha512
	if crypto.SHA512_224.Available() {
		kind, _ := Add("SHA2-512/224", crypto.SHA512_224)
		kind.AddAlias("SHA512_224")
		kind.AddAlias("sha512_224")

		kind.AddAlias("SHA512-224")
		kind.AddAlias("sha512-224")

		kind.AddAlias("SHA-512/224")
		kind.AddAlias("sha-512/224")

		kind.AddAlias("SHA2-512_224")
		kind.AddAlias("sha2-512_224")

		kind.AddAlias("SHA2-512-224")
		kind.AddAlias("sha2-512-224")

		// kind.AddAlias("SHA2-512/224") // Default '/' okay?
		kind.AddAlias("sha2-512/224")

		kind.AddAlias("SHA-2-512_224")
		kind.AddAlias("sha-2-512_224")

		kind.AddAlias("SHA-2-512-224")
		kind.AddAlias("sha-2-512-224")

		kind.AddAlias("SHA-2-512/224")
		kind.AddAlias("sha-2-512/224")
	}

	// import crypto/sha512
	if crypto.SHA512_256.Available() {
		kind, _ := Add("SHA2-512/256", crypto.SHA512_256)
		kind.AddAlias("SHA512_256")
		kind.AddAlias("sha512_256")

		kind.AddAlias("SHA512-256")
		kind.AddAlias("sha512-256")

		kind.AddAlias("SHA512/256")
		kind.AddAlias("sha512/256")

		kind.AddAlias("SHA2-512_256")
		kind.AddAlias("sha2-512_256")

		kind.AddAlias("SHA2-512-256")
		kind.AddAlias("sha2-512-256")

		// kind.AddAlias("SHA2-512/256") // Default '/' okay?
		kind.AddAlias("sha2-512/256")

		kind.AddAlias("SHA-2-512_256")
		kind.AddAlias("sha-2-512_256")

		kind.AddAlias("SHA-2-512-256")
		kind.AddAlias("sha-2-512-256")

		kind.AddAlias("SHA-2-512/256")
		kind.AddAlias("sha-2-512/256")
	}

	// import golang.org/x/crypto/blake2s
	if crypto.BLAKE2s_256.Available() {
		kind, _ := Add("BLAKE2s-256", crypto.BLAKE2s_256)
		kind.AddAlias("blake2s-256")
		kind.AddAlias("BLAKE2s_256")
		kind.AddAlias("blake2s_256")
	}

	// import golang.org/x/crypto/blake2b
	if crypto.BLAKE2b_256.Available() {
		kind, _ := Add("BLAKE2b-256", crypto.BLAKE2b_256)
		kind.AddAlias("blake2b-256")
		kind.AddAlias("BLAKE2b_256")
		kind.AddAlias("blake2b_256")
	}

	// import golang.org/x/crypto/blake2b
	if crypto.BLAKE2b_384.Available() {
		kind, _ := Add("BLAKE2b-384", crypto.BLAKE2b_384)
		kind.AddAlias("blake2b-384")
		kind.AddAlias("BLAKE2b_384")
		kind.AddAlias("blake2b_384")
	}

	// import golang.org/x/crypto/blake2b
	if crypto.BLAKE2b_512.Available() {
		kind, _ := Add("BLAKE2b-512", crypto.BLAKE2b_512)
		kind.AddAlias("blake2b-512")
		kind.AddAlias("BLAKE2b_512")
		kind.AddAlias("blake2b_512")
	}
}
