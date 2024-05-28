
#clang -lelf -lbpf make_map.c -o make_map.o -ggdb3 
clang -Wall send.c -o send.o  -ggdb3 -O0 -Wall
#clang -Wall socket.c -o socket.o -fsanitize=address -ggdb3
#clang -O2 -g -Wall -target bpf -c redirect_progs/host_redirect.c -o xdp_prog.o
#clang -O2 -g -Wall -target bpf -c redirect_progs/host_redirect_map.c -o xdp_prog_map.o
#clang -O2 -g -Wall -target bpf -c redirect_progs/host_redirect_lpm.c -o xdp_prog_lpm.o
clang -O2 -g -Wall -target bpf -c xdp_nop.c -o xdp_nop.o

