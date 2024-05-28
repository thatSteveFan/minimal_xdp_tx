The absolute bare minimum to do TX on an xdp socket, with no libraries, just libc (need libbpf for the xdp program).

dependencies:
latest libbpf from github source
apt: build-essential libelf-dev gcc-multilib pkg-config

steps:
run `./compile.sh`
load xdp program with `ip link set dev <device name> xdp obj ./xdp_nop.o sec xdp`
run with `sudo ./send.c`
