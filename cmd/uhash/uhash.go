package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
)

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
	if fname[0] == '\\' { // Slow but easy...
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
		if text[len(text)-1] != '=' {
			fmt.Fprintf(os.Stderr, "Bad line %d: %s\n", num, otext)
			continue
		}
		text = text[:len(text)-1]

		text = strings.TrimRight(text, " \t")
		if text[len(text)-1] != ')' {
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
	}

	if size > 0 && num != size {
		fmt.Fprintf(os.Stderr, "Mismatched size %d!=%d: %s\n",
			size, num, fname)
		exit_code = 4
	}
}

// ---------------------------------------------------------------

func main() {
	var (
		help     = flag.Bool("h", false, "display this message")
		algo     = flag.String("a", "", `select the digest type to use`)
		check    = flag.Bool("c", false, `read checksums from the FILEs and check them`)
		status   = flag.Bool("status", false, `don't output anything, status code shows success`)
		comments = flag.Bool("comments", false, `output comments, status code shows success`)
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

	_, err := uhash.Lookup(*algo)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
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
