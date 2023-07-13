#include <stdint.h>
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP 0x0800
struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN) /**/
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,        /* data offset */
           th_x2:4;         /* (unused) */
#endif
    u_int8_t  th_flags;       /* control flags */

#define TH_FIN    0x01      /* finished send data */
#define TH_SYN    0x02      /* synchronize sequence numbers */
#define TH_RST    0x04      /* reset the connection */
#define TH_PUSH   0x08      /* push data to the app layer */
#define TH_ACK    0x10      /* acknowledge */
#define TH_URG    0x20      /* urgent! */
#define TH_ECE    0x40   
#define TH_CWR    0x80

    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};



struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
#endif

    u_int8_t ip_tos;       /* type of service */

#define IPTOS_LOWDELAY      0x10
#define IPTOS_THROUGHPUT    0x08
#define IPTOS_RELIABILITY   0x04
#define IPTOS_LOWCOST       0x02

    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;

#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */

    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};


void print_mac(u_int8_t *m){
	printf("%02x:%02x:%02x:%02x:%02x:%02x",m[0],m[1],m[2],m[3],m[4],m[5]);

}

void print_ip(struct in_addr *ip){
	u_int8_t *tmp = (u_int8_t *)ip;
	printf("%d.%d.%d.%d", tmp[0], tmp[1],tmp[2],tmp[3]);
}

void print_tcp_port(u_int16_t *port){
	printf("%d", port[0]);
}

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", (header)->caplen);
		
		struct libnet_ethernet_hdr * eth_hdr = (struct libnet_ethernet_hdr *)packet;
		struct libnet_ipv4_hdr * ipv4_hdr = (struct libnet_ipv4_hdr *)(packet+sizeof(struct libnet_ethernet_hdr));
		struct libnet_tcp_hdr * tcp_hdr = (struct libnet_tcp_hdr *)(ipv4_hdr + sizeof(struct libnet_ipv4_hdr));
		
		print_mac(eth_hdr->ether_shost);
		printf(" ");
		print_mac(eth_hdr->ether_dhost);
		printf("\n");
		print_ip(&(ipv4_hdr->ip_src));
		printf(" ");
		print_ip(&(ipv4_hdr->ip_dst));
		printf("\n");
		print_tcp_port(&(tcp_hdr->th_sport));
		printf(" ");
		print_tcp_port(&(tcp_hdr->th_dport));
		printf("\n");
		if(ntohs(eth_hdr->ether_type)!=ETHERTYPE_IP)
			continue;
	}

	pcap_close(pcap);
}
