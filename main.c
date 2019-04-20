#include<stdio.h>
#include<stdlib.h>
#include<pcap/pcap.h>
#include<arpa/inet.h>
#include"ethernet.h"
#include<ctype.h>
#include<time.h>
//#include<libnet>
#include<unistd.h>
#include<sqlite3.h>
#define SIZE_ETHERNET 14
#define PACKETS_NUMBERS 50

#define ARP_REQUEST 1
#define ARP_REPLY   2


void analyze_packets(u_char *args, const struct pcap_pkthdr *header,const u_char *packet);
void call_arp_spoof(const u_char* packet);
void insert_databases();
char errbuf[PCAP_ERRBUF_SIZE];
int main()
{
    pcap_if_t*  alldevsp=NULL;
    FILE* fp=fopen("log","at+");//日志文件
    FILE* filter=fopen("filter","r");//过滤规则文件
    char filter_str[200];
    int ret=0;

    char* device=pcap_lookupdev(errbuf);//device是设备名
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
	    printf("ip %s\t",net);
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

    pcap_dump_close(dumpfp);

    pcap_freealldevs(alldevsp);
    fclose(fp);
    fclose(filter);
    printf("CODE OVER\n");
    return 0;
}

void analyze_packets(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
   
    const struct mac_header *ethernet=NULL;
    const struct ip_header  *ip=NULL;
    const struct tcp_header *tcp=NULL;
    const unsigned char* payload=NULL;
    sqlite3* db;
    char* sql;
    int ret;

    ret = sqlite3_open("packet.db",&db);
    if(ret)
    {
	 //   fprintf("Can not open databases %s\n",sqlite3_errmsg(db));
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

    ip=(struct ip_header*)(packet+14);
    static unsigned int tcp_num=0,icmp_num=0,udp_num=0;//个数据包捕获的数量 
    unsigned int paclen = header->len;//解析出包长度
    unsigned pacaplen=header->caplen;//解析出包字节数
    char* strtime=ctime((const time_t*)&header->ts.tv_sec);//捕获时间
    static unsigned int count=0;
    static double packet_count=0;//每秒数据包数量
    static unsigned int packets_len=0;//总流量
    static unsigned int tick_count=0;//时间起点
    static double speed=0.0;//流量传输速度
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
		    ethernet->mac_dhost[5]); 

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
   sqlite3_close(db);
   printf("\n");
}

void call_arp_spoof(const u_char *packet)
{
	  libnet_t *handle;        /* Libnet句柄 */
        int packet_size;
        char *device = "eth0";   /* 设备名字,也支持点十进制的IP地址,会自己找到匹配的设备 */
        u_int8_t *src_ip_str = "192.168.128.200";       /* 源IP地址字符串 */
        u_int8_t *dst_ip_str = "192.168.128.88";        /* 目的IP地址字符串 */
        u_int8_t src_mac[6] = {0x00, 0x0c, 0x29, 0x73, 0xfa, 0x86};/* 源MAC */
        u_int8_t dst_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};/* 目的MAC,广播地址 */
        /* 接收方MAC,ARP请求目的就是要询问对方MAC,所以这里填写0 */
        u_int8_t rev_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        u_int32_t dst_ip, src_ip;              /* 网路序的目的IP和源IP */
        char error[LIBNET_ERRBUF_SIZE];        /* 出错信息 */
        libnet_ptag_t arp_proto_tag, eth_proto_tag;

        /* 把目的IP地址字符串转化成网序 */
        dst_ip = libnet_name2addr4(handle, dst_ip_str, LIBNET_RESOLVE);
        /* 把源IP地址字符串转化成网络序 */
        src_ip = libnet_name2addr4(handle, src_ip_str, LIBNET_RESOLVE);

        if ( dst_ip == -1 || src_ip == -1 ) {
            printf("ip address convert error\n");
            exit(-1);
        };
        /* 初始化Libnet,注意第一个参数和TCP初始化不同 */
        if ( (handle = libnet_init(LIBNET_LINK_ADV, device, error)) == NULL ) {
            printf("libnet_init: error [%s]\n", error);
            exit(-2);
        };

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
        };

        /* 构造一个以太网协议块
        You should only use this function when
        libnet is initialized with the LIBNET_LINK interface.*/
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
        };

        packet_size = libnet_write(handle);    /* 发送已经构造的数据包*/

        libnet_destroy(handle);                /* 释放句柄 */
}





