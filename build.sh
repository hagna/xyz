#!/bin/bash

set -x

cd cmd/X
go build
cp X ../../bdist/X_linux_amd64
GOOS="windows" GOARCH="amd64" go build
cp X ../../bdist/X_windows_amd64.exe
GOOS="freebsd" GOARCH="amd64" go build
cp X ../../bdist/X_freebsd_amd64
GOOS="linux" GOARCH="arm" GOARM="7"
cp X ../../bdist/X_linux_arm
GOOS="darwin" GOARCH="amd64" go build
cp X ../../bdist/X_darwin_amd64

cd ../Y
go build
cp Y ../../bdist/Y_linux_amd64
GOOS="windows" GOARCH="amd64" go build
cp Y ../../bdist/Y_windows_amd64.exe
GOOS="freebsd" GOARCH="amd64" go build
cp Y ../../bdist/Y_freebsd_amd64
GOOS="linux" GOARCH="arm" GOARM="7"
cp Y ../../bdist/Y_linux_arm
GOOS="darwin" GOARCH="amd64" go build
cp Y ../../bdist/X_darwin_amd64

cd ../Z
go build
cp Z ../../bdist/Z_linux_amd64
GOOS="windows" GOARCH="amd64" go build
cp Z ../../bdist/Z_windows_amd64.exe
GOOS="freebsd" GOARCH="amd64" go build
cp Z ../../bdist/Z_freebsd_amd64
GOOS="linux" GOARCH="arm" GOARM="7"
cp Z ../../bdist/Z_linux_arm
GOOS="darwin" GOARCH="amd64" go build
cp Z ../../bdist/X_darwin_amd64




