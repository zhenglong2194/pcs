#include<stdio.h>
#include<stdlib.h>
#include<pcap/pcap.h>
#include<arpa/inet.h>
#include"ethernet.h"

#define SIZE_ETHERNET 14

void analyze_packets(u_char *args, const struct pcap_pkthdr *header,const u_char *packet);

char errbuf[PCAP_ERRBUF_SIZE];
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
	    printf("mask %s\n",mask);
    }
    

    ret=pcap_loop(handle,-1,analyze_packets,NULL);
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
    pcap_freealldevs(alldevsp);
    fclose(fp);
    fclose(filter);
    return 0;
}


void analyze_packets(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
    const struct mac_header *ethernet;
    const struct ip_header  *ip;
    const struct tcp_header *tcp;
    const char* payload;


    printf("********************************************\n");
    ethernet = (struct mac_header*)(packet);
    printf("%02x %02x %02x %02x %02x %02x\n",ntohs(ethernet->mac_dhost[0]),ethernet->mac_dhost[1],ethernet->mac_dhost[2],ethernet->mac_dhost[3],ethernet->mac_dhost[4],ethernet->mac_dhost[5]);
    printf("%02x %02x %02x %02x %02x %02x\n",ethernet->mac_shost[0],ethernet->mac_shost[1],ethernet->mac_shost[2],ethernet->mac_shost[3],ethernet->mac_shost[4],ethernet->mac_shost[5]);
    printf("%d\n",ntohs(ethernet->mac_type));
    switch(ntohs(ethernet->mac_type)){
	    case 0x0800:printf("IP PACKET\n");break;
	    case 0x0806:printf("ARP PACKET\n");break;
	    case 0x8035:printf("RARP PACKET\n");break;
    }

    
}
