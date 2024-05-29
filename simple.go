package uhash

import (
	"io"
	"os"
)

func Sum(algo string, b []byte) Checksum {
	kind, _ := Lookup(algo)
	if kind == 0 {
		return nil
	}
	hash := kind.New()
	hash.Write(b)

	return hash.Sum(nil)
}

func SumFile(algo, fname string) (Checksum, int64, error) {
	fin, err := os.Open(fname)
	if err != nil {
		return nil, 0, err
	}
	defer fin.Close()

	kind, err := Lookup(algo)
	if err != nil {
		return nil, 0, err
	}
	h := kind.New()

	size, err := io.Copy(h, fin)
	if err != nil {
		return nil, 0, err
	}

	return h.Sum(nil), size, nil
}
