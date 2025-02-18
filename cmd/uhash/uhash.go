package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/james-antill/uhash"

	// Pull in code for the hashes...
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"

	_ "golang.org/x/crypto/blake2b"
	_ "golang.org/x/crypto/blake2s"
	_ "golang.org/x/crypto/md4"
	_ "golang.org/x/crypto/ripemd160"
	_ "golang.org/x/crypto/sha3"

	// Std. hashes that aren't crypto
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"

	// Now add some custom ones, adding the init stuff else where so people can
	// just import would be great.

	// Maybe official upstream version?
	// "lukechampine.com/blake3"
	// Fast with AVX2 and SSE4.1 acceleration
	"github.com/zeebo/blake3"

	"github.com/cespare/xxhash"

	// djb2/djb2a/sdbm
	"github.com/dgryski/dgohash"

	// github.com/spaolacci/murmur3 is more popular, but twmb seemed to have
	// more testing and amd64 asm.
	"github.com/twmb/murmur3"
)

// Turn an offset into a number, or -1 is it's not a number
func offNum(a string, i int) int {
	if i >= len(a) {
		return -1
	}

	if !(a[i] >= '0' && a[i] <= '9') {
		return -1
	}

	num := 0
	for ; i < len(a) && a[i] >= '0' && a[i] <= '9'; i++ {
		num = num*10 + int(a[i] - '0')
	}

	return num

}

func uiSort(a, b string) int {
	a = strings.ToLower(a)
	b = strings.ToLower(b)

	for i := range a {
		if i >= len(b) {
			return strings.Compare(a, b)
		}
		if a[i] == b[i] {
			continue
		}

		an := offNum(a, i)
		bn := offNum(b, i)

		if an < bn {
			return -1
		}
		return 1
	}

	return strings.Compare(a, b)
}

type lhCSadler32 int

func (u lhCSadler32) New() hash.Hash {
	return adler32.New()
}

func (u lhCSadler32) Size() int {
	return 4
}

type lhCScrc32 int

func (u lhCScrc32) New() hash.Hash {
	return crc32.NewIEEE()
}

func (u lhCScrc32) Size() int {
	return 4
}

var pCastagnoli = crc32.MakeTable(crc32.Castagnoli)

type lhCScrc32Castagnoli int

func (u lhCScrc32Castagnoli) New() hash.Hash {
	return crc32.New(pCastagnoli)
}

func (u lhCScrc32Castagnoli) Size() int {
	return 4
}

var pKoopman = crc32.MakeTable(crc32.Koopman)

type lhCScrc32Koopman int

func (u lhCScrc32Koopman) New() hash.Hash {
	return crc32.New(pKoopman)
}

func (u lhCScrc32Koopman) Size() int {
	return 4
}

var pISO = crc64.MakeTable(crc64.ISO)

type lhCScrc64ISO int

func (u lhCScrc64ISO) New() hash.Hash {
	return crc64.New(pISO)
}

func (u lhCScrc64ISO) Size() int {
	return 8
}

var pECMA = crc64.MakeTable(crc64.ECMA)

type lhCScrc64ECMA int

func (u lhCScrc64ECMA) New() hash.Hash {
	return crc64.New(pECMA)
}

func (u lhCScrc64ECMA) Size() int {
	return 8
}

type lhCSfnv32 int

func (u lhCSfnv32) New() hash.Hash {
	return fnv.New32()
}

func (u lhCSfnv32) Size() int {
	return 4
}

type lhCSfnv32a int

func (u lhCSfnv32a) New() hash.Hash {
	return fnv.New32a()
}

func (u lhCSfnv32a) Size() int {
	return 4
}

type lhCSfnv64 int

func (u lhCSfnv64) New() hash.Hash {
	return fnv.New64()
}

func (u lhCSfnv64) Size() int {
	return 8
}

type lhCSfnv64a int

func (u lhCSfnv64a) New() hash.Hash {
	return fnv.New64a()
}

func (u lhCSfnv64a) Size() int {
	return 8
}

type lhCSfnv128 int

func (u lhCSfnv128) New() hash.Hash {
	return fnv.New128()
}

func (u lhCSfnv128) Size() int {
	return 16
}

type lhCSfnv128a int

func (u lhCSfnv128a) New() hash.Hash {
	return fnv.New128a()
}

func (u lhCSfnv128a) Size() int {
	return 16
}

// Hashes outside the std. lib (x/ counts as std.)
type lhCSblake3256 int

func (u lhCSblake3256) New() hash.Hash {
	return blake3.New()
}
func (u lhCSblake3256) Size() int {
	return 32
}

type lhCSxxHash int

func (u lhCSxxHash) New() hash.Hash {
	return xxhash.New()
}

func (u lhCSxxHash) Size() int {
	return 8
}

type lhCSdjb2 int

func (u lhCSdjb2) New() hash.Hash {
	return dgohash.NewDjb32()
}
func (u lhCSdjb2) Size() int {
	return 4
}

type lhCSdjb2a int

func (u lhCSdjb2a) New() hash.Hash {
	return dgohash.NewDjb32a()
}
func (u lhCSdjb2a) Size() int {
	return 4
}

type lhCSsdbm int

func (u lhCSsdbm) New() hash.Hash {
	return dgohash.NewSDBM32()
}
func (u lhCSsdbm) Size() int {
	return 4
}

type lhCSmurmur32 int

func (u lhCSmurmur32) New() hash.Hash {
	return murmur3.New32()
}
func (u lhCSmurmur32) Size() int {
	return 4
}

type lhCSmurmur64 int

func (u lhCSmurmur64) New() hash.Hash {
	return murmur3.New64()
}
func (u lhCSmurmur64) Size() int {
	return 8
}

type lhCSmurmur128 int

func (u lhCSmurmur128) New() hash.Hash {
	return murmur3.New128()
}
func (u lhCSmurmur128) Size() int {
	return 16
}

func init() {
	uhash.Add("adler32", lhCSadler32(0))
	kind, _ := uhash.Add("crc32", lhCScrc32(0))
	kind.AddAlias("crc32-IEEE")
	uhash.Add("crc32-Castagnoli", lhCScrc32Castagnoli(0))
	uhash.Add("crc32-Koopman", lhCScrc32Koopman(0))
	uhash.Add("crc64-ISO", lhCScrc64ISO(0))
	uhash.Add("crc64-ECMA", lhCScrc64ECMA(0))
	uhash.Add("fnv32", lhCSfnv32(0))
	uhash.Add("fnv32a", lhCSfnv32a(0))
	uhash.Add("fnv64", lhCSfnv64(0))
	uhash.Add("fnv64a", lhCSfnv64a(0))
	uhash.Add("fnv128", lhCSfnv128(0))
	uhash.Add("fnv128a", lhCSfnv128a(0))

	kind, _ = uhash.Add("BLAKE3-256", lhCSblake3256(0))
	kind.AddAlias("blake3-256")
	kind.AddAlias("BLAKE3")
	kind.AddAlias("blake3")

	uhash.Add("xxh64", lhCSxxHash(0))

	uhash.Add("djb2", lhCSdjb2(0))

	uhash.Add("djb2a", lhCSdjb2a(0))

	uhash.Add("sdbm", lhCSsdbm(0))

	kind, _ = uhash.Add("murmur3-32", lhCSmurmur32(0))
	kind.AddAlias("murmur3")

	uhash.Add("murmur3-64", lhCSmurmur64(0))

	uhash.Add("murmur3-128", lhCSmurmur128(0))
}

type parsedChecksumFile struct {
	names []string
	kinds []string
	hashs []string
}

func maybeEscapeFname(name string) string {
	if strings.ContainsAny(name, "\r\n") { // Slow but easy...
		name = strings.ReplaceAll(name, "\r", "\\r")
		name = strings.ReplaceAll(name, "\n", "\\n")
		name = strings.ReplaceAll(name, "\\", "\\\\")
	}

	return name
}

func maybeUnescapeFname(fname string) string {
	if strings.HasPrefix(fname, "\\") { // Slow but easy...
		// We should also check that there are no other \x things
		fname = strings.ReplaceAll(fname, "\\n", "\n")
		fname = strings.ReplaceAll(fname, "\\r", "\r")
		fname = strings.ReplaceAll(fname, "\\\\", "\\")
	}

	return fname
}

func parseChecksumFile(fname, defalgo string) parsedChecksumFile {
	var res parsedChecksumFile

	fin, err := os.Open(fname)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return res
	}
	defer fin.Close()

	scanner := bufio.NewScanner(fin)
	num := 0
	for scanner.Scan() {
		num++
		otext := scanner.Text()
		text := otext
		text = strings.TrimLeft(text, " \t")
		text = strings.TrimSuffix(text, "\n")

		if text == "" {
			continue
		}
		if text[0] == '#' {
			continue
		}

		// Skip PGP/GPG within file signatues...
		if strings.HasPrefix(text, "-----BEGIN ") {
			if strings.HasSuffix(text, " MESSAGE-----") {
				continue
			}
			break
		}

		// Change the default algo...
		var found bool
		text, found = strings.CutPrefix(text, "Hash: ")
		if found {
			defalgo = strings.Trim(text, " \t\r\n")
			continue
		}

		off := strings.IndexAny(text, "( \t")
		if off == -1 {
			fmt.Fprintf(os.Stderr, "Bad line %d: %s\n", num, otext)
			continue
		}
		algo := text[:off]
		text = text[off:]
		text = strings.TrimLeft(text, " \t")

		if text == "" {
			fmt.Fprintf(os.Stderr, "Bad line %d: %s\n", num, otext)
			continue
		}
		if text[0] != '(' {
			// maybe it's just "<checksum> <fname>"
			fname := maybeUnescapeFname(text)
			hash := algo
			res.names = append(res.names, fname)
			res.kinds = append(res.kinds, defalgo)
			res.hashs = append(res.hashs, hash)
			continue
		}
		text = text[1:]

		roff := strings.LastIndexAny(text, " \t")
		if roff == -1 {
			fmt.Fprintf(os.Stderr, "Bad line %d: %s\n", num, otext)
			continue
		}
		hash := text[roff+1:]
		text = text[:roff]

		text = strings.TrimRight(text, " \t")
		if !strings.HasSuffix(text, "=") {
			fmt.Fprintf(os.Stderr, "Bad line %d: %s\n", num, otext)
			continue
		}
		text = text[:len(text)-1]

		text = strings.TrimRight(text, " \t")
		if !strings.HasSuffix(text, ")") {
			fmt.Fprintf(os.Stderr, "Bad line %d: %s\n", num, otext)
			continue
		}
		text = text[:len(text)-1]

		fname = maybeUnescapeFname(text)

		res.names = append(res.names, fname)
		res.kinds = append(res.kinds, algo)
		res.hashs = append(res.hashs, hash)
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	return res
}

// Calling twice is whatever...
func fname2size(fname string) int64 {
	fi, err := os.Stat(fname)
	if err != nil {
		return 0
	}

	return fi.Size()
}

var ErrIsDir = errors.New("Path is a directory")
var ErrIsNotReg = errors.New("Path is not a regular file")

func fname_file(name string) error {
	fi, err := os.Stat(name)
	if err != nil {
		return err
	}

	if fi.IsDir() {
		return fmt.Errorf("Open(%s): %w", name, ErrIsDir)
	}

	if !fi.Mode().IsRegular() {
		return fmt.Errorf("Open(%s): %w", name, ErrIsNotReg)
	}

	return nil
}

var exit_code = 0

func sum_file(fname, algo string, comments bool) {

	if err := fname_file(fname); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	// So the fname is always on one line...
	name := maybeEscapeFname(fname)

	var size int64
	if comments {
		size = fname2size(fname)
		if size > 0 {
			fmt.Printf("# %s: %d bytes\n", name, size)
		}
	}
	fmt.Printf("%s (%s) = ", algo, name)
	hash, num, err := uhash.SumFile(algo, fname)

	fmt.Println(hash)

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exit_code = 4
		return
	}

	if size > 0 && num != size {
		fmt.Fprintf(os.Stderr, "Mismatched size %d!=%d: %s\n",
			size, num, fname)
		exit_code = 4
	}
}

// ---------------------------------------------------------------

func main() {
	uhash.AddStdHashes()

	var (
		help     = flag.Bool("h", false, "display this message")
		algo     = flag.String("a", "", `select the digest type to use`)
		check    = flag.Bool("c", false, `read checksums from the FILEs and check them`)
		status   = flag.Bool("status", false, `don't output anything for --check, status code shows success`)
		comments = flag.Bool("comments", false, `output comments, with sizes`)
		header   = flag.Bool("header", false, `output Hash: header`)
	)

	flag.BoolVar(help, "help", false, "")
	flag.StringVar(algo, "algorithm", "", ``)
	flag.BoolVar(check, "check", false, "")

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if *algo == "" {
		*algo = "SHA256"
	}

	defhash, err := uhash.Lookup(*algo)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		if errors.Is(err, uhash.ErrNotFound) {
			fmt.Fprintln(os.Stderr, "  Available hashes (name: size):")

			var ks []uhash.Kind
			var k uhash.Kind = 1
			for ; !strings.HasPrefix(k.Name(), "Unknown:"); k++ {
				ks = append(ks, k)
			}

			slices.SortFunc(ks, func(a, b uhash.Kind) int {
				return uiSort(a.Name(), b.Name())
			})

			for _, k := range ks {
				d := ""
				if k.Name() == "SHA256" {
					d = " (default)"
				}
				fmt.Fprintf(os.Stderr, "    %s: %d%s\n", k.Name(), k.Size(), d)
			}
			// Show available hashes?
		}
		os.Exit(99)
	}
	if *status { // Do we want to normalize the algo name? Hidden feature.
		*algo = defhash.Name()
	}

	if *header && !*check {
		fmt.Println("Hash:", *algo)
		fmt.Println("")
	}

	for _, arg := range flag.Args() {
		if *check {
			pc := parseChecksumFile(arg, *algo)
			bn := filepath.Dir(arg)

			for i := range pc.names {
				name := pc.names[i]
				kind := pc.kinds[i]
				hash := pc.hashs[i]
				if !*status {
					fmt.Printf("%s: ", name)
				}
				chkhash, _, err := uhash.SumFile(kind, bn+"/"+name)
				if err != nil {
					if errors.Is(err, os.ErrNotExist) {
						fmt.Println("MISSING")
					} else {
						fmt.Println("ERROR")
						fmt.Fprintln(os.Stderr, err)
					}
					if exit_code == 0 {
						// Exit if *status ?
						exit_code = 8
					}
					continue
				}

				if chkhash.EqualString(hash) {
					if !*status {
						fmt.Println("OK")
					}
				} else {
					if *status {
						os.Exit(1)
					}
					fmt.Println("FAIL")
				}
			}
			continue
		}

		// Should be real files or directories...
		sum_file(arg, *algo, *comments)
	}

	os.Exit(exit_code)
}
