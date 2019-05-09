#include<stdio.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<unistd.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<string.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include"my_recv.h"

#define INVALID_USERINFO 'n'
#define VALID_USERINFO   'y'
char name[15];
char order;
int get_userinfo(char* buf,int len)
{
    int i,c;
    if(buf==NULL)
    {
        return -1;
    }
    i=0;
    while(((c=getchar())!='\n')&&(c!=EOF)&&(i<len-2))
    {
        buf[i++]=c;
    }
    buf[i++]='\n';
    buf[i++]='\0';
    return 0;
}

void input_userinfo(int conn_fd,const char* string)
{
    char input_buf[32];
    char recv_buf[BUFSIZE];
    int flag_userinfo;
    printf("%s:",string);
    if(get_userinfo(input_buf,32)<0)
    {
        printf("error return from get_userinfo\n");
        exit(1);
    }
    if(send(conn_fd,input_buf,strlen(input_buf),0)<0)
    {
        my_err("send",__LINE__);
    }
    memset(name,'\0',sizeof(name));
    for(int i=0; i<32; i++)
    {
        if(input_buf[i]!='-')
            name[i]=input_buf[i];
        else
        {
            order=input_buf[i+1];
            break;
        }
    }
}

int main(int argc,char ** argv)
{
    int i,ret,conn_fd,serv_port;
    struct sockaddr_in serv_addr;
    char recv_buf[BUFSIZE];

    if(argc!=5)//参数不足五个报错
    {
        printf("Usage: [-p] [serv_port] [-a] [serv_address]\n");
        exit(1);
    }
    memset(&serv_addr,0,sizeof(struct sockaddr_in));//初始化地址
    serv_addr.sin_family=AF_INET;//tcp/ip协议
    for(i=1; i<argc; i++) //获得服务器的端口与地址
    {
        if(strcmp("-p",argv[i])==0)
        {
            serv_port=atoi(argv[i+1]);//端口
            if(serv_port<0||serv_port>65535)//检查合法性
            {
                printf("invalid serv_addr.sin_port\n");
                exit(1);
            }
            else
            {
                serv_addr.sin_port=htons(serv_port);
            }
            continue;
        }
        if(strcmp("-a",argv[i])==0)
        {
            if(inet_aton(argv[i+1],&serv_addr.sin_addr)==0)//写入ip地址
            {
                printf("invalid server ip address\n");
                exit(1);
            }
            continue;
        }
    }
    if(serv_addr.sin_port==0||serv_addr.sin_addr.s_addr==0)
    {
        printf("Usage: [-p] [serv_addr.sin_port] [-a] [serv_address]\n");
        exit(1);
    }

    conn_fd=socket(AF_INET,SOCK_STREAM,0);//创建tcp套接字
    if(conn_fd<0)
        my_err("socket",__LINE__);
    //向服务器端请求建立链接connect
    if(connect(conn_fd,(struct sockaddr*)&serv_addr,sizeof(struct sockaddr))<0)
    {
        my_err("connect",__LINE__);
    }

    input_userinfo(conn_fd,"send");
    int FILE_WT;
    int num;
//	int ii;
    FILE_WT=open(name,O_RDWR|O_CREAT);
    unsigned char buffer[2048];
    memset(buffer,'\0',sizeof(buffer));
    //write()向服务端发送数据   read读取服务端数据
    if(order=='s')//请求下载文件
        while(recv(conn_fd,buffer,sizeof(buffer)-1,0)>0)
        {
            for(num=sizeof(buffer)-1; buffer[num]=='\0'&&num>0; num--);
            printf("%d\n",num++);
            write(FILE_WT,buffer,num);
            memset(buffer,'\0',sizeof(buffer));
        }
    if(order=='d')//删除指定文件
        printf("delete %s\n",name);
    if(order=='c')//创建规定配置文件
        printf("create a file %s",name);
    if(order=='t')//上传文件
    {
        printf("update file %s",name);
        long int ret;
        int FILE_RD;
        FILE_RD=open(name,'r');
        while(1)
        {
            if(ret=read(FILE_RD,buffer,sizeof(buffer)-1))
                send(conn_fd,buffer,ret,0);
            else
                break;
        }
        close(FILE_RD);
    }
    printf("COPY OVER\n");
    printf("\n");
    close(conn_fd);//关闭连接
    close(FILE_WT);
    return 0;
}


