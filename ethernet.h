#ifndef ETHERNET_H
#define ETHERNET_H

#define ETHER_ADDR_LEN 6
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
struct mac_header{
	u_char mac_dhost[ETHER_ADDR_LEN];
	u_char mac_shost[ETHER_ADDR_LEN];
	u_short mac_type;
};

struct ip_header{
	u_char ip_vhl;
	u_char ip_tos;
	u_short ip_len;
	u_short ip_id;
	u_short ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
	u_char ip_ttl;
	u_char ip_p;
	u_short ip_sum;
	struct in_addr ip_src,ip_dst;
};

#define IP_HL(ip) (((ip)->ip_vhl)&0x0f)
#define IP_V(ip)  (((ip)->ip_vhl)>>4)

typedef u_int tcp_seq;

struct tcp_header{
	u_short th_sport;
	u_short th_dport;
	tcp_seq th_seq;
	tcp_seq th_ack;
	u_char th_offx2;
#define TH_OFF(th)  (((th)->th_offx2 & 0xf0)>>4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0X04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define Th_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE_TH_CWR)
	u_short th_win;
	u_short th_sum;
	u_short th_urp;
};

struct udp_header{
	u_short th_sport;
	u_short th_dport;
	u_short length;
	u_short th_sum;
};

struct arp_header{
	u_short har_typ;;
	u_short pro_typ;
	u_char  har_size;
	u_char  pro_size;
	u_short opcode;
	u_char mac_shost[ETHER_ADDR_LEN];
	struct in_addr ip_src;
	u_char mac_dhost[ETHER_ADDR_LEN];
	struct in_addr ip_dst;
};

struct ip_mac{
	char ip[17];
	char mac[18];
};

#endif
