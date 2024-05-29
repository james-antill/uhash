package uhash

import (
	"hash"
	"io"
)

type Multi struct {
	iow io.Writer

	ks []Kind
	hs []hash.Hash
}

func (m *Multi) Write(b []byte) (n int, err error) {
	return m.iow.Write(b)
}

func (m *Multi) Checksums() []Result {
	var res []Result

	for i, h := range m.hs {
		res = append(res, Result{m.ks[i], h.Sum(nil)})
	}

	return res
}

func NewMulti(kinds ...Kind) *Multi {
	ks := []Kind{}
	hs := []hash.Hash{}
	hios := []io.Writer{}
	for _, kind := range kinds {
		h := kind.New()
		ks = append(ks, kind)
		hs = append(hs, h)
		hios = append(hios, h)
	}

	iow := io.MultiWriter(hios...)

	return &Multi{iow, ks, hs}
}
