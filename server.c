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
#include"my_recv.h"

#define SERV_PORT 4600
#define LISTENQ   12
#define IVAILDE_VALUE 0
#define VAILDE_VALUE 1
struct file_name
{
    char file[15];
};
struct file_name filename[]= {"dump.pcap","filter","log","packet.db","ip_form","testfile"};
int main()
{
    int sock_fd,conn_fd;
    int optval;
    int flags=IVAILDE_VALUE;
    int ret;
    int name_num;
    pid_t pid;
    socklen_t cli_len;
    struct sockaddr_in cli_addr,serv_addr;
    char recv_buf[128];

    sock_fd=socket(AF_INET,SOCK_STREAM,0);//创建套接字
    if(sock_fd<0)
    {
        my_err("socket",__LINE__);
    }
    optval=1;
    if(setsockopt(sock_fd,SOL_SOCKET,SO_REUSEADDR,(void*)&optval,sizeof(int))<0)
    {
        my_err("setsockopt",__LINE__);
    }

    memset(&serv_addr,0,sizeof(struct sockaddr_in));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERV_PORT);
    serv_addr.sin_addr.s_addr=htonl(INADDR_ANY);

    if(bind(sock_fd,(struct sockaddr*)&serv_addr,sizeof(struct sockaddr_in))<0)
    {
        my_err("bind",__LINE__);
    }

    if(listen(sock_fd,LISTENQ)<0)
    {
        my_err("listen",__LINE__);
    }

    cli_len = sizeof(struct sockaddr_in);
    while(1)
    {
        conn_fd  = accept(sock_fd,(struct sockaddr*)&cli_addr,&cli_len);
        if(conn_fd<0)
        {
            my_err("accept",__LINE__);
        }
        printf("accept a new client IP:%s\n",inet_ntoa(cli_addr.sin_addr));
        if((pid=fork())==0)
        {
            while(1)
            {
                if((ret=recv(conn_fd,recv_buf,sizeof(recv_buf),0))<0)
                {
                    perror("recv");
                    exit(1);
                }
                recv_buf[ret-1]='\0';
                char order;
                char name[15];
                order=recv_buf[ret-2];
                strncpy(name,recv_buf,ret-3);
                name[ret-2]='\0';
                printf("name %s\n%ld\n",name,strlen(name));
			for(int i=0; i<6; i++)
			{
			    if(strncmp(name,filename[i].file,strlen(name))==0)
				flags=VAILDE_VALUE;
			}
			if(flags==0)
			{
			    printf("此文件不存在\n");
			    break;
			}
			if(order=='s')
			{
			    long int ret;
			    int num=0;
			    unsigned char buffer[2048];
			    int FILE_RD;
			    FILE_RD=open(name,'r');
			    long filesize=0;
			    struct stat statbuf;
			    stat(name,&statbuf);
			    filesize=statbuf.st_size;
			    printf("filsize%ld\n",filesize);
			    send(conn_fd,&filesize,sizeof(long),0);
			    long size=filesize;
			    while(1)
			    {
				   
    			         if(read(FILE_RD,buffer,sizeof(buffer))>0)
				{
					size-=sizeof(buffer);
					printf("size %ld\n",size);
				  if(size<0)
				  {
				    send(conn_fd,buffer,size+sizeof(buffer),0);
				    break;
				  }
				    send(conn_fd,buffer,sizeof(buffer),0);
                                    memset(buffer,'\0',sizeof(buffer));
				}
				else
				    break;
			    }
			    printf("fprintf file over\n");
			    close(FILE_RD);
			    break;
			}
			if(order=='d')
			{
			    remove(name);
			    break;
			}
			if(order=='c')
			{
			    int FILE_C=open(name,O_CREAT|O_EXCL,S_IRUSR|S_IWUSR);
			    close(FILE_C);
			    break;
			}
			if(order=='t')
			{
				printf("-t\n");
			    remove(name);
			    int FILE_WT;
			    int num;
			    FILE_WT=open(name,O_RDWR|O_CREAT);
			    unsigned char buffer[2048];
			    memset(buffer,'\0',sizeof(buffer));
			    while(recv(conn_fd,buffer,sizeof(buffer)-1,0)>0)
                           {
                              for(num=sizeof(buffer)-1; buffer[num]=='\0'&&num>0; num--);
                              write(FILE_WT,buffer,num+1);
                              memset(buffer,'\0',sizeof(buffer));
                           }
		           printf("-t over\n");
		          close(FILE_WT);
                          break;
                         }
            }
            close(sock_fd);
            close(conn_fd);
            exit(0);
        }
        else
            close(conn_fd);
    }
    return 0;
}
