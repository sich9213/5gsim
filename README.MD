Install MongoDB:

$ sudo apt update

$ sudo apt install mongodb

$ sudo systemctl start mongodb 

$ sudo systemctl enable mongodb 


Setting TUN device:

$ sudo ./misc/netconf.sh

Install the dependencies:

$ sudo apt install python3-pip python3-setuptools python3-wheel ninja-build build-essential flex bison git libsctp-dev libgnutls28-dev libgcrypt-dev libssl-dev libidn11-dev libmongoc-dev libbson-dev libyaml-dev libnghttp2-dev libmicrohttpd-dev libcurl4-gnutls-dev libnghttp2-dev meson

Compile:

$ meson build --prefix=\`pwd\`/install

$ ninja -C build

Run:

$ ./build/tests/registration/registration
