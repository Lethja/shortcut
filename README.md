# rproxy

## Overview
rproxy is an HTTP file caching proxy
intended to save bandwidth by caching updates to packages in Linux repositories.
When a device connects to rproxy and requests a file,
it will be downloaded to the device and stored on the machine running rproxy.
Any later requests for the same file by other devices will be served from the local cache,
saving bandwidth and potentially allowing for faster downloads.

## Building
rproxy is a typical Cargo project.

Building is as simple as:
```sh
cargo build --release
```
To build with HTTPS support:
```sh
cargo build --features https --release
```
The binary will be built in `target/release/rproxy`.

## Usage
### Cache Path
rproxy needs to know where to store and look up any cached files it downloads.
You can set this by defining the `X_PROXY_CACHE_PATH` environment variable
to a folder that allows read/write permissions. 
If the path doesn't already exist, rproxy will attempt to create it.

#### Examples
##### Unix Shell
```sh
export X_PROXY_CACHE_PATH="/tmp/rproxy"
./rproxy
```
##### Windows Command Prompt
```cmd
SET X_PROXY_CACHE_PATH="C:\Temp\rproxy"
rproxy.exe
```
### Listen Address
rproxy can optionally bind to a particular network address. 
You can set this by defining the `X_PROXY_HTTP_LISTEN_ADDRESS` environment variable 
to an address and port.

When `X_PROXY_HTTP_LISTEN_ADDRESS` is not set, 
rproxy will default to listening for any address on port `3142`.

#### Examples
- `X_PROXY_HTTP_LISTEN_ADDRESS="127.0.0.1:8080"`
- `X_PROXY_HTTP_LISTEN_ADDRESS="[::1]:8080"`

### Testing with wget
To test that the proxy is working on the same machine with `wget` run the following command twice
```
http_proxy=http://127.0.0.1:3142 https_proxy=https://127.0.0.1:3142 wget --no-check-certificate https://github.com/Lethja/rproxy/archive/refs/heads/master.zip
```
> Using `--no-check-certificate` to test the proxy is safe in this case
since `127.0.0.1` is a loopback address to the same machine.\
rproxy will still verify `github.com`s certificate when it makes the request.

## Caveats
Cached content never expires.
If the rproxy cache disk has low free disk space, you will need to manually delete files.