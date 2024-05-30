ethtool -L ens4 tx 4 && ethtool -L ens4 rx 4 && sudo ip link set ens4 xdp obj xdp_nop.o sec xdp
