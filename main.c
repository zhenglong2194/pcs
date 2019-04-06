#include<stdio.h>
#include<stdlib.h>
#include<pcap/pcap.h>
#include<arpa/inet.h>
#include"ethernet.h"
#include<ctype.h>
#include<time.h>
#include<libnet>
#include<unistd.h>
#define SIZE_ETHERNET 14

void analyze_packets(u_char *args, const struct pcap_pkthdr *header,const u_char *packet);
void call_arp_spoof(const u_char* packet);
void call_database
char errbuf[PCAP_ERRBUF_SIZE];1
int main()
{
    pcap_if_t*  alldevsp=NULL;
    FILE* fp=fopen("log","at+");//日志文件
    FILE* filter=fopen("filter","r");//过滤规则文件
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
    

    ret=pcap_loop(handle,-1,analyze_packets,(u_char *)dumpfp);
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
    return 0;
}

void analyze_packets(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
   
    const struct mac_header *ethernet=NULL;
    const struct ip_header  *ip=NULL;
    const struct tcp_header *tcp=NULL;
    const unsigned char* payload=NULL;

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
    count++;//统计数据包总数
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
   printf("\n");
}



void call_arp_spoof(const u_char *packet)
{

}









