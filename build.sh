#!/bin/bash

VTAG="$(git rev-list HEAD --count)-$(git describe --long --dirty --abbrev=4 --tags --always)"

build () {
go build -ldflags="-X main.version=${VTAG}" && echo "built $(pwd) ${GOOS} ${GOARCH}"
}

cd X
CGO_ENABLED=0 build
cp X ../bdist/X_linux_amd64
GOOS="windows" GOARCH="amd64" build
cp X ../bdist/X_windows_amd64.exe
GOOS="freebsd" GOARCH="amd64" build
cp X ../bdist/X_freebsd_amd64
GOOS="linux" GOARCH="arm" GOARM="7"
cp X ../bdist/X_linux_arm
GOOS="darwin" GOARCH="amd64" build
cp X ../bdist/X_darwin_amd64

cd ../Y
CGO_ENABLED=0 build
cp Y ../bdist/Y_linux_amd64
GOOS="windows" GOARCH="amd64" build
cp Y ../bdist/Y_windows_amd64.exe
GOOS="freebsd" GOARCH="amd64" build
cp Y ../bdist/Y_freebsd_amd64
GOOS="linux" GOARCH="arm" GOARM="7"
cp Y ../bdist/Y_linux_arm
GOOS="darwin" GOARCH="amd64" build
cp Y ../bdist/Y_darwin_amd64

cd ../Z
CGO_ENABLED=0 build
cp Z ../bdist/Z_linux_amd64
GOOS="windows" GOARCH="amd64" build
cp Z ../bdist/Z_windows_amd64.exe
GOOS="freebsd" GOARCH="amd64" build
cp Z ../bdist/Z_freebsd_amd64
GOOS="linux" GOARCH="arm" GOARM="7"
cp Z ../bdist/Z_linux_arm
GOOS="darwin" GOARCH="amd64" build
cp Z ../bdist/Z_darwin_amd64




