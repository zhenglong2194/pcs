#include<stdio.h>
#include<stdlib.h>
#include<pcap/pcap.h>
#include<arpa/inet.h>
#include"ethernet.h"
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
    
    pcap_freealldevs(alldevsp);
    fclose(fp);
    fclose(filter);
    return 0;
}


void analyze_packets(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{

}
