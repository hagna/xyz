#!/bin/bash

set -x
VTAG="$(git rev-list HEAD --count)-$(git describe --long --dirty --abbrev=4 --tags --always)"

build () {
go build -ldflags="-X main.version=${VTAG}" && echo "built $(pwd) ${GOOS} ${GOARCH}"
}


mktgz () {
	mkdir work
	PLATFORM=$1
	ARCH=$2
	cd X; GOOS=$PLATFORM GOARCH=$ARCH build; cd ..; cp "X/X${EXT}" work/. 
	cd Y; GOOS=$PLATFORM GOARCH=$ARCH build; cd ..; cp "Y/Y${EXT}" work/.
	cd Z; GOOS=$PLATFORM GOARCH=$ARCH build; cd ..; cp "Z/Z${EXT}" work/.
	cd work
	tar -cvzf "${PLATFORM}_${ARCH}.tgz" *
	mv "${PLATFORM}_${ARCH}.tgz" ../bdist/.
	cd ..
	rm -rf work
}

CGO_ENABLED=0 mktgz linux amd64
exit
mktgz darwin amd64
mktgz freebsd amd64
mktgz linux arm
EXT=".exe" mktgz windows amd64
