
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <stdlib.h>
#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>

#include <stdio.h>
#include <unistd.h>
#include <locale.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <errno.h>
#include <libgen.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <linux/if_xdp.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <time.h>

#include <net/ethernet.h>
#include <netinet/udp.h>


#define handle_error(msg) { fprintf(stderr, "%s %s(%d)\n", msg, strerror(errno), errno); exit(1); }
const char* pathname = "/tmp/container1/uds";
#define QUEUE 0
#define XSK_MAX_ENTRIES 1
#define OLD_KERNEL 0

#define DEBUG 0
#define RING_SIZE (2048 * 32)
#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
#include "xsk_ops.h" //needs RING_SIZE
struct xsk_socket {
  int fd;
  uint64_t rx_packets;
  uint64_t rx_bytes;
  uint64_t tx_packets;
  uint64_t tx_bytes;
};


static uint64_t gettime()
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(1);
	}
	return (uint64_t) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static void *stats_poll(void *arg)
{
        unsigned int interval = 2;
        struct xsk_socket *xsk = arg;
        setlocale(LC_NUMERIC, "en_US");
        uint64_t prev_time = 0, prev_tx_packets = 0, cur_time, cur_tx_packets;
        double period = 0.0, tx_pps = 0.0;
        while (1) {
                sleep(interval);
                if (prev_time == 0) {
                          prev_time = gettime();
                          prev_tx_packets = READ_ONCE(xsk->tx_packets);
                          continue;
                }
                cur_time = gettime();
                period = ((double) (cur_time - prev_time) / NANOSEC_PER_SEC);
		prev_time = cur_time;
                cur_tx_packets = READ_ONCE(xsk->tx_packets);
                tx_pps = (cur_tx_packets - prev_tx_packets) / period;
		prev_tx_packets = cur_tx_packets;
                printf("tx pps: %'10.0f\n", tx_pps);
        }
}

void* set_umem(int xsk, long size)
{
	// should be page-aligned
	void* umem = mmap(NULL,
			  size,
			  PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_ANONYMOUS,
			  -1, 0);
	if(umem == (void *) -1)
		handle_error("mapping umem failed");

	struct xdp_umem_reg umem_reg = {.addr = umem, 
		                        .len = size, 
					.chunk_size=4096, 
					.headroom=0};
	if(setsockopt(xsk, SOL_XDP, XDP_UMEM_REG, &umem_reg, sizeof(umem_reg))){
		handle_error("setting umem failed");
	}
	return umem;
}

void setup_rings(int xsk, struct umem_ring *fill, struct umem_ring *com, struct kernel_ring *rx, struct kernel_ring *tx)
{
	int fill_ring_size = RING_SIZE;
	if(setsockopt(xsk, SOL_XDP, XDP_UMEM_FILL_RING, &fill_ring_size, sizeof(int)) < 0){
		handle_error("setting fill ring failed");
	}
	int com_ring_size = RING_SIZE;
	if(setsockopt(xsk, SOL_XDP, XDP_UMEM_COMPLETION_RING, &com_ring_size, sizeof(int)) < 0){
		handle_error("setting completion ring failed");
	}
	int tx_ring_size = RING_SIZE;
	if(setsockopt(xsk, SOL_XDP, XDP_TX_RING, &tx_ring_size, sizeof(int)) < 0){
		handle_error("setting tx ring failed");
	}
	int rx_ring_size = RING_SIZE;
	if(setsockopt(xsk, SOL_XDP, XDP_RX_RING, &rx_ring_size, sizeof(int)) < 0){
		handle_error("setting rx ring failed");
	}


	struct xdp_mmap_offsets offs;
	socklen_t optlen = sizeof(offs);
	int err = getsockopt(xsk, SOL_XDP, XDP_MMAP_OFFSETS, &offs, &optlen);
	if(err)
		handle_error("error getting offsets");
	
	void* fill_map = mmap(NULL,
			offs.fr.desc + RING_SIZE * sizeof(__u64),
		   	PROT_READ | PROT_WRITE, 
			MAP_SHARED | MAP_POPULATE,
			xsk,
		  	XDP_UMEM_PGOFF_FILL_RING);
	if(fill_map == MAP_FAILED)
		handle_error("error mapping fill ring");
	fill->size = RING_SIZE;
	fill->producer = fill_map + offs.fr.producer;
	fill->consumer = fill_map + offs.fr.consumer;
	fill->ring = fill_map + offs.fr.desc;
	fill->cached_prod = 0;
	fill->cached_cons = RING_SIZE;

	void* com_map = mmap(NULL,
			offs.cr.desc + RING_SIZE * sizeof(__u64),
		   	PROT_READ | PROT_WRITE, 
			MAP_SHARED | MAP_POPULATE,
			xsk,
		  	XDP_UMEM_PGOFF_COMPLETION_RING);
	if(com_map == MAP_FAILED)
		handle_error("error mapping completion ring");
	com->size = RING_SIZE;
	com->producer = com_map + offs.cr.producer;
	com->consumer = com_map + offs.cr.consumer;
	com->ring = com_map + offs.cr.desc;
	com->cached_prod = 0;
	com->cached_cons = 0;

	void* rx_map = mmap(NULL, 
		      offs.rx.desc + RING_SIZE * sizeof(struct xdp_desc),
		      PROT_READ | PROT_WRITE, 
		      MAP_SHARED | MAP_POPULATE,
		      xsk, 
		      XDP_PGOFF_RX_RING);
	if(rx_map == MAP_FAILED)
		handle_error("error mapping rx ring");
	rx->size = RING_SIZE;
	rx->producer = rx_map + offs.rx.producer;
	rx->consumer = rx_map + offs.rx.consumer;
	rx->ring = rx_map + offs.rx.desc;
	rx->cached_prod = 0;
	rx->cached_cons = 0;

	void* tx_map = mmap(NULL, 
		      offs.tx.desc + RING_SIZE * sizeof(struct xdp_desc),
		      PROT_READ | PROT_WRITE, 
		      MAP_SHARED | MAP_POPULATE,
		      xsk, 
		      XDP_PGOFF_TX_RING);
	if(tx_map == MAP_FAILED)
		handle_error("error mapping tx ring");
	tx->size = RING_SIZE;
	tx->producer = tx_map + offs.tx.producer;
	tx->consumer = tx_map + offs.tx.consumer;
	tx->ring = tx_map + offs.tx.desc;
	tx->cached_prod = 0;
	tx->cached_cons = RING_SIZE;

	//printf("debugging producer for fill: %d\n", debug_umem_prod(fill));
}

int xdp_socket()
{
	int xsk = socket(AF_XDP, SOCK_RAW, 0);
	if(xsk < 0)
		handle_error("error making xsk");
	return xsk;
}

void set_limit(int pid, long limit)
{
	struct rlimit rlimit = {.rlim_cur=limit, .rlim_max=limit};
	int err = prlimit(pid, RLIMIT_MEMLOCK, &rlimit, NULL);
	if(err)
		handle_error("setting limit failed");
}

void bind_xsk(int xsk, int ifidx)
{

	printf("binding to device %d, queue %d\n", ifidx, QUEUE);
	struct sockaddr_xdp sxdp;
	memset(&sxdp, 0, sizeof(sxdp));
        sxdp.sxdp_family = PF_XDP; 
	sxdp.sxdp_ifindex = ifidx;
	sxdp.sxdp_queue_id = QUEUE;
	sxdp.sxdp_flags = XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY ;
	//sxdp.sxdp_flags = XDP_ZEROCOPY ;
	//sxdp.sxdp_flags = XDP_USE_NEED_WAKEUP;
	//sxdp.sxdp_flags = 0;
	sxdp.sxdp_flags = 0;
	if (bind(xsk, (struct sockaddr *)&sxdp, sizeof(struct sockaddr_xdp))) {
		handle_error("bind socket failed");
	}
	printf("bound to socket\n");

}

/* Compute checksum for count bytes starting at addr, using one's complement of one's complement sum*/
static unsigned short compute_checksum(unsigned short *addr, unsigned int count) {
  register unsigned long sum = 0;
  while (count > 1) {
    sum += * addr++;
    count -= 2;
  }
  //if any bytes left, pad the bytes and add
  if(count > 0) {
    sum += ((*addr)&htons(0xFF00));
  }
  //Fold sum to 16 bits: add carrier to result
  while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
  }
  //one's complement
  sum = ~sum;
  return ((unsigned short)sum);
}
static void compute_ip_checksum(struct iphdr* iphdrp){
  iphdrp->check = 0;
  iphdrp->check = compute_checksum((unsigned short*)iphdrp, iphdrp->ihl<<2);
}


void create_packet(void* data_, int payload_len) {
	char* data = (char*) data_;
	struct ether_header *eh = (struct ether_header *)data;
	memcpy(eh->ether_dhost, "\x00\x11\x22\x33\x44\x55", ETH_ALEN);
	memcpy(eh->ether_shost, "\xaa\xbb\xcc\xdd\xee\xff", ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	struct iphdr *iph = (struct iphdr *) (data + sizeof(struct ether_header));
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len);
	iph->id = htons(54321);
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->saddr = inet_addr("10.128.0.80"); 
	iph->daddr = inet_addr("10.128.0.81");

	struct udphdr *udph = (struct udphdr *)(data + sizeof(struct ether_header) + sizeof(struct iphdr));
	udph->source = htons(5555);
	udph->dest = htons(8888);
	udph->len = htons(sizeof(struct udphdr) + payload_len);

	char* payload = (data + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr));
	memset(payload, 'A', payload_len);

	compute_ip_checksum(iph);
}

int send_batch(int fd, void* umem, struct umem_ring *com, struct kernel_ring *tx, void* pkt, int len) {

	int batch_size = RING_SIZE;

	int num_reserved = xsk_kr_prod_reserve(tx, batch_size);
	if (num_reserved < batch_size) {
		if(DEBUG) {
			printf("no tx reserved\n");
		}
		return 0;
	}
	char *umem_char = ((char*) (umem));
	for (int i=0; i<batch_size; i++) {
		memcpy(umem_char + i*4096, pkt, len);
		xsk_kr_prod_write(tx, i*4096, len);
	}
	xsk_kr_prod_submit(tx, batch_size);
	if(DEBUG) {
		printf("Submitted packet, waiting completion\n");
		debug_kernel_ring(tx);
	}
	int total_recieved = 0;
	while(total_recieved < batch_size) {
		if(DEBUG) {
			printf("Kicking fd %d.\n", fd);
		}
		int ret = sendto(fd , NULL, 0, MSG_DONTWAIT, NULL, 0);
		if (ret == -1 && DEBUG) {
			printf("Got %d from sendto.\n", errno);
		}
		int recieved_packets = xsk_umem_cons_peek(com, (batch_size+3)/4);
		if (recieved_packets == 0) {
			if(DEBUG) {
				printf("still waiting on completion\n");
				debug_kernel_ring(tx);
				debug_umem_ring(com);
				sleep(1);
			}
			continue;
		}
		if(DEBUG) {
			printf("Got %d packets\n", recieved_packets);
			debug_umem_ring(com);
		}
		int idx = xsk_umem_cons_read(com);
		if(DEBUG) {
			printf("Got back idx: %d\n", idx);
			debug_kernel_ring(tx);
			debug_umem_ring(com);
		}
		xsk_umem_cons_release(com, recieved_packets);
		total_recieved += recieved_packets;
		
	}
	return batch_size;


}

void dumb_poll(struct xsk_socket *xsk, void* umem, struct umem_ring *fill, struct kernel_ring *rx)
{
	while(1)
	{
	}
}


int main(int argc, char** argv)
{

	if (argc < 2)
	{
		printf("usage: socket.o ifidx");
		return -1;
	}
	int ifidx = atoi(argv[1]);
	printf("making xsk on ifidx %d\n", ifidx);
	pid_t pid = getpid();
	printf("setting limit on pid %d\n", pid);
	set_limit(pid, 1l<<34); //4G
	int xsk = xdp_socket();
	printf("got xsk %d\n", xsk);
	void* umem = set_umem(xsk, 4096l * (long)RING_SIZE);
	struct umem_ring fill, com;
	struct kernel_ring rx, tx;
	setup_rings(xsk, &fill, &com, &rx, &tx);
	printf("set up rings\n");

	bind_xsk(xsk, ifidx);
//	load_xdp_program("./guest_prog.o", "xdp");
//	add_to_xsk_map(xsk, xsk_map_name, pid);
	struct xsk_socket xsk_sock;
        memset(&xsk_sock, 0, sizeof(struct xsk_socket));
        xsk_sock.fd = xsk;

	void* golden_packet = malloc(256);
	create_packet(golden_packet, 10);

        pthread_t stats_poll_thread;
	printf("creating stats thread\n");
        int ret = pthread_create(&stats_poll_thread, NULL, stats_poll, &xsk_sock);
        if (ret) {
              handle_error("error creating stats thraed");
        }
	while(1) {
		int sent_packets = send_batch(xsk, umem, &com, &tx, golden_packet, 256);
		xsk_sock.tx_packets += sent_packets;
	}
	//dumb_poll(&xsk_sock, umem, &fill, &rx);


	printf("Done\n");

	// char* args[] = {"/bin/bash", NULL};
	// execvp(args[0], args);
	// char* args[] = {"ip", "addr", "show", NULL};
	// execvp(args[0], args);
}
