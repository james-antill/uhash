#! /bin/sh -e

name=uhash

upx cmd/$name/$name.bin.darwin-amd64 || true
upx cmd/$name/$name.bin.linux-amd64  || true

cp  -a cmd/$name/$name.bin.darwin-amd64 ~/bin/$name
# scp -p cmd/$name/$name.bin.linux-amd64  slicehost7:bin/$name
