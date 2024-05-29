package uhash

type devnull struct{}

var _ Hash = devnull{}

func (u devnull) Write(b []byte) (n int, err error) {
	return 0, nil /// io.Discard?
}

func (u devnull) Sum(b []byte) []byte {
	return nil
}
func (u devnull) Reset() {
}
func (u devnull) Size() int {
	return 0
}
func (u devnull) BlockSize() int {
	return 0
}

func (u devnull) Kind() Kind {
	return 0
}
