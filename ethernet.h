#ifndef ETHERNET_H
#define ETHERNET_H

#define ETHER_ADDR_LEN 6
typedef unsigned char u_char;
typedef unsigned short u_short;
struct Mac{
	u_char Mac_dhost[ETHER_ADDR_LEN];
	u_char Mac_shost[ETHER_ADDR_LEN];
	u_short Mac_type;
};




#endif
