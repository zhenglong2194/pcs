#ifndef ETHERNET_H
#define ETHERNET_H
#include<stdio.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<unistd.h>
#include<string.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<errno.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<pcap/pcap.h>
#include<ctype.h>
#include<time.h>
#include<string.h>
#include<sqlite3.h>
#include<net/if.h>
#include<pthread.h>
#include"my_recv.h"

#define SERV_PORT 4600
#define LISTENQ   12
#define IVAILDE_VALUE 0
#define VAILDE_VALUE 1
#define ETHER_ADDR_LEN 6

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;

struct time_packet{
	long int se;
	long int us;
};

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

#define IP_HL(ip) (((ip)->ip_vhl)&0x0f)//低四位长度
#define IP_V(ip)  (((ip)->ip_vhl)>>4)//高四位版本号

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
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;
	u_short th_sum;
	u_short th_urp;
};

struct udp_header{
	u_short th_sport;
	u_short th_dport;
	u_short th_len;
	u_short th_sum;
};

struct icmp_header{
	u_char  ic_typ;
	u_char  ic_cod;
	u_short ic_sum;
	u_int   ic_oth;
};

struct igmpv1_header{
	u_char  ig_typ;
	u_char  ig_res;
	u_short ig_sum;
	struct in_addr ig_ip;
};
struct arp_header{
	u_short har_typ;
	u_short pro_typ;
	u_char  har_size;
	u_char  pro_size;
	u_short opcode;
	u_char mac_shost[ETHER_ADDR_LEN];
	u_char  ip_src[4];
	u_char mac_dhost[ETHER_ADDR_LEN];
	u_char  ip_dst[4];
};

struct ip_mac{
	char ip[17];
	unsigned char mac[6];
};

struct NUM{
	int total_len;
	int packet_count;
	float speed;
	int tcp_num;
	int udp_num;
	int icmp_num;
	int igmp_num;
	int arp_num;
	int rarp_num;
};

struct PAC{
	int len;
	int caplen;
	char time[24];
	int sport;
	int dport;
	char sip[17];
	char dip[17];
	int protoco;
};

struct SIZE{
	int length1;
	int length2;
	int length3;
	int length4;
	int length5;
	int length6;
	int length7;
};
#endif
