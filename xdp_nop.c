#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>



SEC("xdp")
int xdp_redirect(struct xdp_md *ctx)
{
	return XDP_PASS;
}
