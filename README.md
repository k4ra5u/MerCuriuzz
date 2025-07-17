# MerCuriuzz
The following tests were completed on ubuntu24.04
## Environment
```bash
sudo apt update && sudo apt upgrade -y

sudo apt install -y build-essential pkg-config openssl libssl-dev zlib1g-dev gyp

sudo apt install -y curl git net-tools htop

sudo apt install -y gcc-multilib g++-multilib cmake make python3-pip llvm-dev libclang-dev clang ninja-build

pip install wsproto starlette --break-system-packages
```
Install cargo:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustc --version && cargo --version  
```


## Target Installation
```bash
cd ~/MerCuriuzz/vendors/app_deploy
mkdir -p certs && cd certs
openssl req -x509 -newkey rsa:4096 -nodes -keyout server.key -out server.crt -days 365 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

### Lsquic
```bash
git clone https://boringssl.googlesource.com/boringssl
cd boringssl
cmake . &&  make
cd ..
git clone https://github.com/litespeedtech/lsquic.git
cd lsquic
git submodule update --init
mkdir build && cd build
cmake -DBORINGSSL_DIR=$HOME/MerCuriuzz/vendors/app_deploy/boringssl ..
make -j$(nproc)
```
```bash
cd build/bin
./http_server -s 0.0.0.0:25443 -L ERROR -r ./ -c 127.0.0.1,$HOME/MerCuriuzz/vendors/app_deploy/certs/server.crt,$HOME/MerCuriuzz/vendors/app_deploy/certs/server.key
```
### Neqo
```bash
git clone https://github.com/mozilla/neqo.git
cd neqo
wget https://ftp.mozilla.org/pub/security/nss/releases/NSS_3_111_RTM/src/nss-3.111-with-nspr-4.36.tar.gz
tar -zxvf nss-3.111-with-nspr-4.36.tar.gz
mv nss-3.111-with-nspr-4.36 nss-3.111
cd nss-3.111/nspr
./configure
make && sudo make install
cd ../nss
./build.sh
cd ../../
NSS_DIR=./nss-3.111/nss NSS_TARGET=./nss-3.111/nss/ cargo build
```
```bash
target/debug/neqo-server -d ./test-fixture/db 0.0.0.0:30443
```
### h2o
```bash
cd $HOME/MerCuriuzz/vendors/app_deploy
git clone https://github.com/h2o/h2o.git
cd h2o
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=$HOME/MerCuriuzz/vendors/app_deploy/h2o/Debug -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
make install
cd ..
cp -r examples/h2o Debug/etc
vim Debug/etc/h2o.conf
```
replace like this($HOME may not work, you should replace it with your home directory path):
```conf
# to find out the configuration commands, run: h2o --help

num-threads: 1
listen: &ssl_listen
  port: 38440
  ssl:
    certificate-file: $HOME/MerCuriuzz/vendors/app_deploy/certs/server.crt
    key-file: $HOME/MerCuriuzz/vendors/app_deploy/certs/server.key
    minimum-version: TLSv1.3
    cipher-preference: server
    cipher-suite: "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"
    # Oldest compatible clients: Firefox 27, Chrome 30, IE 11 on Windows 7, Edge, Opera 17, Safari 9, Android 5.0, and Java 8
    # see: https://wiki.mozilla.org/Security/Server_Side_TLS
# The following three lines enable HTTP/3
listen:
  <<: *ssl_listen
  type: quic

header.set: "Alt-Svc: h3-25=\":38440\""
quic-nodes:
  self: 1
  mapping:
   1: "127.0.0.1:38440"
hosts:
  "alternate.localhost.examp1e.net:38440":
    paths:
      /:
        file.custom-handler:
          extension: .php
          fastcgi.connect:
            port: /tmp/fcgi.sock
            type: unix
    access-log: /dev/stdout
```
```bash
Debug/bin/h2o 
```
### Aioquic
```bash
git clone https://github.com/aiortc/aioquic.git
pip install . --break-system-packages
pip install wsproto starlette --break-system-packages
python3 examples/http3_server.py -c $HOME/MerCuriuzz/vendors/app_deploy/certs/server.crt --port 4443
```

## Building
The following is a sample that compiles a MerCuriuzz minimizer instance.
```bash
cd $HOME/MerCuriuzz/vendors/

git clone https://github.com/k4ra5u/LibAFL
git clone --recursive https://github.com/k4ra5u/quiche
unzip libnyx.zip
unzip packer.zip
unzip QEMU-Nyx.zip
unzip libnyx.zip
cd ../fuzzers/network_quic_fuzz
export RUSTFLAGS="-C link-arg=-lstdc++"
CARGO_TARGET_DIR=target  cargo build
```
Usage:
Before testing, you need to configure the startup parameters and judgment parameters of the two QUIC implementations, which are located in the start and judge directories of the main program project. You need to replace the parameters of the original <program name>.sh file with the program path of the local machine, and modify the content of the ports file in the start directory, which describes the CPU resources and port information used by each QUIC implementation. 

Run:`target/debug/network_quic_fuzz <procA> <procB>`

*Configuration files for QUIC applications*
> h2o:            h2o.conf,
> haproxy:        quix.cfg,
> msquic:         src/tools/sample/sample.c,
> nginx:          nginx.conf,
> s2n-quic:       quic_echo_server.rs,
