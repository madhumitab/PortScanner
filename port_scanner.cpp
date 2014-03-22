#include <iostream>	//for printf
#include <string.h> //memset
#include <sys/socket.h>	//for socket ofcourse
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <netdb.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <math.h>
#include <sstream>
#include <fstream>
#include <pthread.h>
#include <cstring>
#include <string>
#include <netinet/udp.h>
#include<queue>
#include <sys/wait.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <math.h>
#include <sstream>
#include <fstream>
#include <ifaddrs.h>
#include <linux/icmp.h>

using namespace std;
pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;

queue<string> q;
int queue_size,proto_count = 0;
string scan_list[7],source_ip;
int protocols[256];
int sockfd,rv;
pcap_t *recv_handle;
struct ip_list
{
	char ip[INET6_ADDRSTRLEN];
};

void *get_in_addr(sockaddr *sa1)
{
	if (sa1->sa_family == AF_INET) {
		return &(((sockaddr_in*)sa1)->sin_addr);
	}

	return &(((sockaddr_in6*)sa1)->sin6_addr);
}

void sigchld_handler(int s)
{
	while(waitpid(-1, NULL, WNOHANG) > 0);
}


struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};



struct dataFromMain
{
	int thread_id,sockfd,target,port_count;
	string arg,s,x;
sockaddr_in sin;
};

unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

unsigned short icmp_csum(unsigned short *addr, int len)
{
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;
    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }
    /* mop up an odd byte, if necessary */
    if (nleft == 1)
    {
      *(u_char *) (&answer) = *(u_char *) w;
      sum += answer;
    }
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);       /* add hi 16 to low 16 */
    sum += (sum >> 16);               /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return (answer);
}


int received_packet(u_char *args, const pcap_pkthdr *header, const u_char *packet_recv, int work)
{
	stringstream string_out;
	sockaddr_in add;
	ethhdr *eth_r, *eth_s;
	iphdr *iph_r, *iph_s;
	tcphdr *tcphdr_r, *tcphdr_s;
	eth_r = (ethhdr *)packet_recv;
	iph_r = (iphdr*)(packet_recv + sizeof(ethhdr));
	char target_ip[INET_ADDRSTRLEN];
	add.sin_addr.s_addr = iph_r->daddr;	
	if(inet_ntop(AF_INET, &(add.sin_addr.s_addr), target_ip, INET_ADDRSTRLEN)==NULL)
	{}
//	cout<<"Protocol: "<<(int)iph_r->protocol<<endl;
	if(work==0)
	{
		if((int)iph_r->protocol == 1)
		{
//			cout<<"ICMP received"<<endl;	
			cout<<"IP\t\t\tDEST PROTOCOL\tSCAN\t\tRESULT"<<endl;
			cout<<target_ip<<"\t\tICMP\t\tProtocol\t";	
			return 1;
		}
		else if((int)iph_r->protocol == 6)			
		{
			tcphdr_r = (tcphdr*)(packet_recv + sizeof(iphdr) + sizeof(ethhdr));
			cout<<"IP\t\t\tDEST PORT\tSCAN\tRESULT"<<endl;
			cout<<target_ip<<"\t\t"<<ntohs(tcphdr_r->dest)<<"\t\t";	
			if(tcphdr_r->syn==1)
				return 61;	//SYN
			else if(tcphdr_r->ack==1)
				return 62;	//ACK
			else if(tcphdr_r->fin==1)
			{
				if(tcphdr_r->psh==1)
					return 65;	//XMAS
				else
					return 64;	//FIN
			}
			else
				return 63;	//NULL
		}	
		else if((int)iph_r->protocol == 17)
		{
			cout<<"IP\t\t\tDEST PROTOCOL\tSCAN\t\tRESULT"<<endl;
			cout<<target_ip<<"\t\tUDP\t\tProtocol\t";	
			return 17;
		}
		else
		{
			cout<<"IP\t\t\tDEST PROTOCOL\tSCAN\t\tRESULT"<<endl;
			cout<<target_ip<<"\t\t"<<(int)iph_r->protocol<<"\t\tProtocol\t";	
			return 20;
		}
	}
	else if(work == 1)
	{
		cout<<"ICMP Response"<<endl;
	}
	else if(work == 17)
	{
		if((int)iph_r->protocol == 1)
		{
			cout<<"Closed"<<endl;
			return 0;
		}
		else if((int)iph_r->protocol == 17)
		{
			cout<<"Open"<<endl;
			return 0;
		}		
	}
	else if(work == 20)
	{
		if((int)iph_r->protocol == 1)
		{
			cout<<"Closed"<<endl;
			return 0;
		}
		else if((int)iph_r->protocol == 17)
		{
			cout<<"Open"<<endl;
			return 0;
		}		
	}	
	else if(work == 61)
	{
		cout<<"SYN\t";
		if((int)iph_r->protocol == 1)
		{
			cout<<"Filtered"<<endl;
			return 0;
		}
		else if((int)iph_r->protocol == 6)			
		{
			tcphdr_r = (tcphdr*)(packet_recv + sizeof(iphdr) + sizeof(ethhdr));
			if(tcphdr_r->rst==1)
			{
				cout<<"Closed"<<endl;
				return 0;
			}
			else if(tcphdr_r->ack==1)
			{
				cout<<"Open"<<endl;
				return 0;
			}
		}
	}
	else if(work == 62)
	{
		cout<<"ACK\t";
		if((int)iph_r->protocol == 1)
		{
			cout<<"Filtered"<<endl;
			return 0;
		}
		else if((int)iph_r->protocol == 6)			
		{
			tcphdr_r = (tcphdr*)(packet_recv + sizeof(iphdr) + sizeof(ethhdr));
			if(tcphdr_r->rst==1)
			{
				cout<<"Unfiltered"<<endl;
				return 0;
			}
		}
	}
	else if(work == 63)
	{
		cout<<"NULL\t";
		if((int)iph_r->protocol == 1)
		{
			cout<<"Filtered"<<endl;
			return 0;
		}
		else if((int)iph_r->protocol == 6)			
		{
			tcphdr_r = (tcphdr*)(packet_recv + sizeof(iphdr) + sizeof(ethhdr));
			if(tcphdr_r->ack==1)
			{
				cout<<"Unfiltered"<<endl;
				return 0;
			}
		}
	}
	else if(work == 64)
	{
		cout<<"FIN\t";
		if((int)iph_r->protocol == 1)
		{
			cout<<"Filtered"<<endl;
			return 0;
		}
		else if((int)iph_r->protocol == 6)			
		{
			tcphdr_r = (tcphdr*)(packet_recv + sizeof(iphdr) + sizeof(ethhdr));
			if(tcphdr_r->ack==1)
			{
				cout<<"Unfiltered"<<endl;
				return 0;
			}
		}
	}
	else if(work == 65)
	{
		cout<<"XMAS\t";
		if((int)iph_r->protocol == 1)
		{
			cout<<"Filtered"<<endl;
			return 0;
		}
		else if((int)iph_r->protocol == 6)			
		{
			tcphdr_r = (tcphdr*)(packet_recv + sizeof(iphdr) + sizeof(ethhdr));
			if(tcphdr_r->ack==1)
			{
				cout<<"Unfiltered"<<endl;
				return 0;
			}
		}
	}

}

void send_to_port(string x)
{
//pthread_mutex_lock( &mutex1 );
//cout<<"inside send_to_port"<<endl;
//cout<<"1"<<endl;
int r_len=0;
bool loop=true;
int scan_type;

//cout<<"2";
pseudo_header psh;
char *saveptr1;
string scan_to_compare;
addrinfo *servinfo,info, *p,*server2;	
sockaddr_in sin,dest,sout;
const u_char *packet_sent, *packet_recv;
pcap_pkthdr header;
//cout<<"hdjdhjdfhdfjjdf"<<endl;
char datagram[4096] ,  *data , *pseudogram;
int count=0,sockfd_2;
string output;
//cout<<"before input"<<endl;
char r_buf[1540],input[75]="Get /index.html HTTP/1.0\r\n Host: www.rushilshah.com\r\n \r\n \r\n";
char *pch,*pch2,*pch3;
char * ptr1=new char[x.size()+1];
ptr1[x.size()]=0;
memcpy(ptr1,x.c_str(),x.size());

//pthread_mutex_lock( &mutex1 );
pch=strtok(ptr1,"|");

pch2=strtok(NULL,"|");
pch3=strtok(NULL,"|");
//cout<<"pch3:::"<<pch3;
//pthread_mutex_unlock( &mutex1 );
int port_to_send=atoi(pch2);
scan_to_compare=pch3;
//memset(&info,0,sizeof(info));
//	info.ai_family = AF_UNSPEC;
//	info.ai_socktype = SOCK_STREAM;

//cout<<"pch2:::"<<pch2<<endl;

	//zero out the packet buffer

 	memset (datagram, 0, sizeof(datagram));
	

	//IP header
	iphdr *iph = (iphdr *) datagram;
	
	//TCP header
	tcphdr *tcph = (tcphdr *) (datagram + sizeof (iphdr));
	

	udphdr *udp = (udphdr *)(datagram + sizeof(iphdr));
	
	//ICMP header
//	icmp *icmph = (icmp *)(datagram + sizeof(icmp));
	icmphdr *icmp = (icmphdr*) (datagram + sizeof(icmphdr));

	//Data part
	data = datagram + sizeof(iphdr) + sizeof(tcphdr);


	//some address resolution
		//strcpy(source_ip , "140.182.147.11");
		//sin.sin_family = AF_INET;
		//sin.sin_port = htons(port_to_send);
//		sin.sin_addr.s_addr = inet_addr (list[0].c_str());
		//if(inet_pton(AF_INET, pch, &(sin.sin_addr.s_addr))==1)


if(inet_pton(AF_INET, source_ip.c_str(), &(sout.sin_addr.s_addr))==1)
		{}		
		sin.sin_family = AF_INET;
		sin.sin_port = htons(port_to_send);
//		sin.sin_addr.s_addr = inet_addr (list[0].c_str());
		if(inet_pton(AF_INET, pch, &(sin.sin_addr.s_addr))==1)
		{}
		

//input="Get /index.html HTTP/1.1\r\n Host: www.google.com\r\n \r\n \r\n";
//110 :- pop3
//code added for verifying sevices
bool to_check = true;
if(port_to_send==80 || port_to_send==25 || port_to_send == 587 || port_to_send == 43 || port_to_send==143 || port_to_send==110 || port_to_send==22)
{
//cout<<"port_to_send"<<port_to_send<<endl;
memset(&info,0,sizeof(info));
	info.ai_family = AF_UNSPEC;
	info.ai_socktype = SOCK_STREAM;
//cout<<"pch::"<<pch<<endl;
//cout<<"pch2::"<<pch2<<endl;
//cout<<"soucre_ip"<<source_ip<<endl;
if((getaddrinfo(pch,pch2, &info, &server2))!=0)
	{
		exit(1);
	}	
	
	
//cout<<"sockfd_2"<<sockfd_2<<endl;
//cout<<"server->ai_addr"<<inet_ntoa(sin.sin_addr)<<endl;
//cout<<"server->ai_addrlen"<<server2->ai_addrlen<<endl;
/*
for(p=server2;p!=NULL;p=p->ai_next)
{
cout<<"server->ai_addr"<<inet_ntoa(sin.sin_addr)<<endl;
cout<<"server->ai_addrlen"<<server2->ai_addrlen<<endl;

if((sockfd_2 = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
	{
		cerr<<"\nClient: socket";
		continue;
	}

cout<<"sockfd_2"<<sockfd_2<<endl;
	if(connect(sockfd_2, p->ai_addr,p->ai_addrlen) == -1)
	{
		close(sockfd_2);
		cerr<<"\nClient: connect error"<<endl;
		continue;
	}
	break;
}*/
			if((sockfd_2 = socket(server2->ai_family, server2->ai_socktype, server2->ai_protocol)) == -1)
			{
				cerr<<"Client: socket";
			}
			if(connect(sockfd_2, server2->ai_addr,server2->ai_addrlen) == -1)
			{
				cout<<"Port is Closed"<<endl;
				to_check = false;
			}			
			else
			{
				//cout<<"after connect"<<endl;
				//cout<<"strlen:::"<<strlen(input);

				if(port_to_send==80)
				{
				if(send(sockfd_2,input,50,0)==-1)
				{
				cerr<<"Error sending";
				}
				}
				if(port_to_send==43)
				{
				cout<<"inside port_to_Send 43"<<endl;
				if(send(sockfd_2,"129.79.247.4",500,0)==-1)
				{
				cerr<<"Error sending";
				}
				}
				else
				{
				//cout<<"inside else of sending error";
				}
				if((r_len = recv(sockfd_2, r_buf,1500,0))!=-1)
				{
		//			cerr<<"Recieve";
		//			exit(1);	
		//			cout<<"Size: "<<r_len<<endl;		
					for(int i=0;i<(r_len-1);i++)
					{
						output = output+r_buf[i];
					}
					cout<<"output:::"<<output<<endl;
				}
			}
int str_len=output.size();
if(port_to_send==80 && to_check == true)
{
cout<<"The service with version running is ::"<<output.substr(0,8)<<endl;
//cout<<"The version for the service is ::"<<output.substr(4,4)<<endl;
}
else if((port_to_send==587||port_to_send==25) && to_check == true)
{
cout<<"The service with version is ::"<<output.substr(27,28)<<endl;
}
else if(port_to_send==22 && to_check == true)
{
cout<<"The service with version is ::"<<output.substr(0,7)<<endl;
}
else if(port_to_send==110 && to_check == true)
{
cout<<"The service with version is ::"<<output.substr(0,str_len)<<endl;
}
else if(port_to_send==143 && to_check == true)
{
cout<<"The service with version is ::"<<output.substr(0,str_len)<<endl;
}
else if(port_to_send==43 && to_check == true)
{
cout<<"The service with version is ::"<<output<<endl;
}
}
		//Fill in the IP Header
		iph->ihl = 5;
		iph->version = 4;
		iph->tos = 0;
		iph->tot_len = sizeof (iphdr) + sizeof (tcphdr) + strlen(data);
		iph->id = htonl (54321);	//Id of this packet
		iph->frag_off = 0;
		iph->ttl = 255;
//		iph->protocol = 6;
		iph->check = 0;		//Set to 0 before calculating checksum
		iph->saddr = sout.sin_addr.s_addr;	//Spoof the source ip address
		iph->daddr = sin.sin_addr.s_addr;
		//Ip checksum
		iph->check = csum ((unsigned short *) datagram, iph->tot_len);
	
		//Ip checksum
		iph->check = csum ((unsigned short *) datagram, iph->tot_len);
		//cout<<"before scan"<<endl;
		

//cout<<"Scan to comp::"<<scan_to_compare<<endl;
if(scan_to_compare.compare("Protocol")==0)
		{
				cout<<"Protocol count::"<<proto_count<<endl;
			for(int j=0;j<proto_count;j++)
			{
				if(protocols[j]==1)
				{
					data = datagram + sizeof(iphdr) + sizeof(tcphdr);
					cout<<"Creating ICMP"<<endl;
					iph->tot_len = sizeof(iphdr) + sizeof(icmphdr);
					icmp->type = ICMP_ECHO;
					icmp->code = 0;
					icmp->un.echo.id = 0;
					icmp->un.echo.sequence = 0;
					icmp->checksum = 0;
					icmp->checksum = csum((unsigned short *)data, (sizeof(icmphdr)+strlen(data)));
					cout<<"chksum:::"<<icmp->checksum<<endl;
//					cout<<"CSUM::"<<icmp_csum((unsigned short *)icmp, sizeof(icmphdr))<<endl;
//					cout<<"CSUM2::"<<csum((unsigned short *)datagram , iph->tot_len)<<endl;
//					cout<<"IP CSUM::"<<csum ((unsigned short *) datagram, iph->tot_len)<<endl;
/*					icmph->icmp_type = ICMP_ECHO;
					icmph->icmp_code = 0;
					icmph->icmp_id = 0;
					icmph->icmp_seq = 0;
					icmph->icmp_cksum = csum ((unsigned short *)icmph , sizeof(icmph));
*/					iph->protocol = IPPROTO_ICMP;
					iph->check = csum ((unsigned short *) datagram, iph->tot_len);
				}
				else if(protocols[j]==6)	
				{
					iph->tot_len = sizeof (iphdr) + sizeof (tcphdr) + strlen(data);
					iph->protocol = 6;
					iph->check = csum ((unsigned short *) datagram, iph->tot_len);
					tcph->source = htons (1234);
					tcph->dest = htons (port_to_send);
					tcph->seq = 0;
					tcph->ack_seq = 0;
					tcph->doff = 5;	//tcp header size
					tcph->fin=0;	
					tcph->syn=1;
					tcph->rst=0;
					tcph->psh=0;
					tcph->ack=0;
					tcph->urg=0;
					tcph->window = htons (5840);	/* maximum allowed window size */
					tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
					tcph->urg_ptr = 0;
					
					psh.source_address = inet_addr( source_ip.c_str() );
					psh.dest_address = sin.sin_addr.s_addr;
					psh.placeholder = 0;
					psh.protocol = IPPROTO_TCP;	
					psh.tcp_length = htons(sizeof(tcphdr) + strlen(data) );	
	
					//cout<<"Creating TCP"<<endl;
					int psize = sizeof(pseudo_header) + sizeof(tcphdr) + strlen(data);
					pseudogram = new char[psize];
					memcpy(pseudogram , (char*) &psh , sizeof (pseudo_header));
					memcpy(pseudogram + sizeof(pseudo_header) , tcph , sizeof(tcphdr) + strlen(data));
	
					tcph->check = csum( (unsigned short*) pseudogram , psize);
				}
				else if(protocols[j]==17)
				{
					cout<<"Creating UDP..."<<endl;
					iph->tot_len = sizeof(iphdr) + sizeof(udphdr) + strlen(data);
					iph->protocol = 17;
					udp->source = htons(1234);
					udp->dest = htons(port_to_send);
					udp->len = htons(sizeof(udphdr));
					udp->check = htons(0); 
					iph->check = csum ((unsigned short *) datagram, iph->tot_len);
				}
				else
				{
					cout<<"Creating RAW..."<<endl;
					iph->tot_len = sizeof(iphdr) + strlen(data);
					iph->protocol = protocols[j];
					iph->check = csum ((unsigned short *) datagram, iph->tot_len);					
				}
				//IP_HDRINCL to tell the kernel that headers are included in the packet
				int one = 1;
				const int *val = &one;
	
				if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
				{
					cout<<"Error setting IP_HDRINCL";
					exit(0);
				}
	
				{
					//Send the packet
					if (sendto (sockfd, datagram, iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
					{
						cout<<"sendto failed";
					}
					//Data send successfully
					else
					{
//						cout<<"Packet Send...Length : "<<iph->tot_len<<endl;
					}
				}
		loop = true;
		while(loop)
		{
			packet_sent = pcap_next(recv_handle, &header);
			if((scan_type=received_packet(NULL, &header, packet_sent, 0))!=0)
			{
//				cout<<"";
				cout<<"Scan::"<<scan_type<<endl;
			}
			packet_recv = pcap_next(recv_handle, &header);
			if(scan_type == 61 ||scan_type == 62 ||scan_type == 63 ||scan_type == 64 ||scan_type == 65 ||scan_type != 0)
			{
				if(received_packet(NULL, &header, packet_recv, scan_type)==0)
				{
//					cout<<"Done"<<endl;
					loop = false;
					break;
				}
			}
		}

	
			}			
		}
		
		else
		{	
			iph->protocol = 6;
			if(scan_to_compare.compare("SYN")==0)
			{
				cout<<"IN SYN::"<<endl;
				tcph->source = htons (1234);
				tcph->dest = htons (port_to_send);
				tcph->seq = 0;
				tcph->ack_seq = 0;
				tcph->doff = 5;	//tcp header size
				tcph->fin=0;	
				tcph->syn=1;
				tcph->rst=0;
				tcph->psh=0;
				tcph->ack=0;
				tcph->urg=0;
				tcph->window = htons (5840);	/* maximum allowed window size */
				tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
				tcph->urg_ptr = 0;
			}
			else if(scan_to_compare.compare("ACK")==0)
			{
				//TCP Header
				tcph->source = htons (1234);
				tcph->dest = htons (port_to_send);
				tcph->seq = 0;
				tcph->ack_seq = 0;
				tcph->doff = 5;	//tcp header size
				tcph->fin=0;
				tcph->syn=0;
				tcph->rst=0;
				tcph->psh=0;
				tcph->ack=1;
				tcph->urg=0;
				tcph->window = htons (5840);	/* maximum allowed window size */
				tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
				tcph->urg_ptr = 0;
			}
			else if(scan_to_compare.compare("NULL")==0)
			{
				//TCP Header
				tcph->source = htons (1234);
				tcph->dest = htons (port_to_send);
				tcph->seq = 0;
				tcph->ack_seq = 0;
				tcph->doff = 5;	//tcp header size
				tcph->fin=0;
				tcph->syn=0;
				tcph->rst=0;
				tcph->psh=0;
				tcph->ack=0;
				tcph->urg=0;
				tcph->window = htons (5840);	/* maximum allowed window size */
				tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
				tcph->urg_ptr = 0;
			}
			else if(scan_to_compare.compare("FIN")==0)
			{
				//TCP Header
				tcph->source = htons (1234);
				tcph->dest = htons (port_to_send);
				tcph->seq = 0;
				tcph->ack_seq = 0;
				tcph->doff = 5;	//tcp header size
				tcph->fin=1;
				tcph->syn=0;
				tcph->rst=0;
				tcph->psh=0;
				tcph->ack=0;
				tcph->urg=0;
				tcph->window = htons (5840);	/* maximum allowed window size */
				tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
				tcph->urg_ptr = 0;
			}
			else if(scan_to_compare.compare("XMAS")==0)
			{
				//TCP Header
				tcph->source = htons (1234);
				tcph->dest = htons (port_to_send);
				tcph->seq = 0;
				tcph->ack_seq = 0;
				tcph->doff = 5;	//tcp header size
				tcph->fin=1;
				tcph->syn=0;
				tcph->rst=0;
				tcph->psh=1;
				tcph->ack=0;
				tcph->urg=1;
				tcph->window = htons (5840);	/* maximum allowed window size */
				tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
				tcph->urg_ptr = 0;
			}
			//Now the TCP checksum
			psh.source_address = inet_addr( source_ip.c_str() );
			psh.dest_address = sin.sin_addr.s_addr;
			psh.placeholder = 0;
			psh.protocol = IPPROTO_TCP;	
			psh.tcp_length = htons(sizeof(tcphdr) + strlen(data) );	
	
			//cout<<"Creating TCP"<<endl;
			int psize = sizeof(pseudo_header) + sizeof(tcphdr) + strlen(data);
			pseudogram = (char *)malloc(psize);
			memcpy(pseudogram , (char*) &psh , sizeof (pseudo_header));
			memcpy(pseudogram + sizeof(pseudo_header) , tcph , sizeof(tcphdr) + strlen(data));
	
			tcph->check = csum( (unsigned short*) pseudogram , psize);
			//cout<<"TCP SUM::"<<csum( (unsigned short*) pseudogram , psize)<<endl;
		
	
		//IP_HDRINCL to tell the kernel that headers are included in the packet
		int one = 1;
		const int *val = &one;
//		cout<<"sockfd inside function:::"<<sockfd<<endl;
		if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
		{
			cout<<"Error setting IP_HDRINCL"<<endl;
			exit(0);
		}
	
	//	cout<<"Ready to send"<<endl;
		//loop if you want to flood :)
		//while (1)
		{
			//Send the packet
			if (sendto (sockfd, datagram, iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
			{
				cout<<"sendto failed";
			}
			//Data send successfully
			else
			{
				cout<<"Packet Send...Length : "<<iph->tot_len<<endl;
			}
		}
//		bool loop=true;
//		int scan_type;
		while(loop)
		{
			packet_sent = pcap_next(recv_handle, &header);
			if((scan_type=received_packet(NULL, &header, packet_sent, 0))!=0)
			{
//				cout<<"";
//				cout<<"Scan::"<<scan_type<<endl;
			}
			packet_recv = pcap_next(recv_handle, &header);
			if(scan_type == 61 ||scan_type == 62 ||scan_type == 63 ||scan_type == 64 ||scan_type == 65 ||scan_type !=0)
			{
				if(received_packet(NULL, &header, packet_recv, scan_type)==0)
				{
//					cout<<"Done"<<endl;
					loop = false;
					break;
				}
			}
		}
	}


//pthread_mutex_unlock( &mutex1 );
}

void *call_func_scan(void *dummyPtr)
{
string x="";
//dataFromMain *port_data;
//int sockfd=port_data->sockfd;
//cout<<"sockfd inside func"<<endl;
 pthread_mutex_lock( &mutex1 );
//cout<<"inside call_func_scan";
while(!q.empty())
{
			//cout<<"After Mutex"<<endl;		
x=q.front();
	cout<<"Current Job:::"<<x<<endl;
	q.pop();
send_to_port(x);


 }
pthread_mutex_unlock( &mutex1 );
//cout<<"x2::::::"<<x<<endl;
//send_to_port(x);
}







int main (int argc, char *argv[])
{
	
	//addrinfo hints, *servinfo, *p;
	pcap_if_t *recv_dev , *dev;
	 //Handle of the device that shall be sniffed
	char errbuf[PCAP_ERRBUF_SIZE]="TimeOut has occured";
	string dev_name;
	pcap_pkthdr header;	/* The header that pcap gives us */		
	const u_char *packet;
	sockaddr_in sin;
	pseudo_header psh;
	int loop_var,timeout_var;
	//string s="";
int count=0;
	 bpf_program fp;		/* The compiled filter expression */
	 char filter_exp[] = "port 1234 || ip proto \\icmp";	/* The filter expression */
	 bpf_u_int32 mask;		/* The netmask of our sniffing device */
	 bpf_u_int32 net;		/* The IP of our sniffing device */

	string arg,port_line,ip,ip_pre,scan,scan_1,scan_2,file,ip_line,p_range;
	string scan_list[7], *list, source, help_command;
	char source_host[128],source_ipp[INET_ADDRSTRLEN];
	int pos_dot,pos_dash,pos_comma,pos_slash,port_r1,port_r2,comma,pi,pii,ip_range,proto_r1,proto_r2,list_count;
	int ports[1024];
	sockaddr_in test;
	sockaddr_in6 test6;
	FILE *findFile;
	fstream help,sample;
	bool set_ip = false,set_port = false;
	int port_count = 0, ip_count = 0;
  	hostent *he;
    	in_addr **addr_list;
	ifaddrs *localAddr=NULL;
	string conName;
dataFromMain dfm[100];
pthread_t thread_id[100];
int num_threads;
const u_char *packet_sent, *packet_recv;
//char  ip_port[]="129.79.245.211|90";
//char * pch=NULL;	
//cout<<"hiiiiiiiii"<<endl;
//	pch=strtok(ip_port,"|");
//cout<<endl<<"first pch"<<pch<<endl;
//	while(pch!=NULL)
//	{
//	cout<<"hi"<<endl;
//	pch=strtok(NULL,"|");

//cout<<pch<<endl;
//	}


//Part 1
	for(int i=1;i<argc;i++)
	{
		arg = argv[i];
		if(arg.compare("--help")==0)
		{
			help.open("help");
			if(help.is_open())
			{
				while(! help.eof())
				{
					getline(help,help_command);
					cout<<help_command<<endl;
				}
			}	
			exit(0);
		}


		else if(arg.compare("--speedup")==0)
		{
		char *num=argv[i+1];
		num_threads=atoi(num);
	//	cout<<"num:::"<<num<<endl;
		}
		else if(arg.compare("--ports")==0)
		{
			memset(ports,0,sizeof(ports));
			port_line = argv[i+1];
			pii = 0;				
			if((pos_dash = port_line.find("-",0))>0)
			{
				port_r1 = atoi(port_line.substr(0,pos_dash).c_str());	
				//cout<<port_r1<<endl;			
				port_r2 = atoi(port_line.substr(pos_dash+1,port_line.size()-(pos_dash+1)).c_str());	
				//cout<<port_r2<<endl;			
				for(int i=0;i<=(port_r2-port_r1+1);i++)
				{
					ports[i] = port_r1 + i;
					port_count++;
//					cout<<ports[i-port_r1]<<endl;
				}
			}
			else if((pos_comma = port_line.find(",",0))>0)
			{
				comma = -1;
				while(pos_comma>0)
				{
					port_r1 = atoi(port_line.substr(comma+1,pos_comma-comma).c_str());	
					ports[pii] = port_r1;
					pii++;
					port_count++;
					comma = pos_comma;
					pos_comma = port_line.find(",",pos_comma+1);
//					cout<<pos_comma<<endl;
				}
				port_r2 = atoi(port_line.substr(comma+1,port_line.size()-(comma+1)).c_str());				
				ports[pii] = port_r2;
				port_count++;
			//	for(int i=0;i<=pi;i++)
				//	cout<<ports[i]<<endl;
			}
			else
			{
				ports[0] = atoi(port_line.c_str());
				port_count++;
			}
			set_port = true;
		}
		else if(arg.compare("--ip")==0)
		{
			ip = argv[i+1];
			if(inet_pton(AF_INET, ip.c_str(), &(test.sin_addr))==1 ||inet_pton(AF_INET6, ip.c_str(), &(test6.sin6_addr))==1)
			{
				//cout<<"IP:"<<ip<<endl;
			}
			list = new string[1];
			list[0] = ip;	
			set_ip = true;
			list_count = 1;
		}
		else if(arg.compare("--prefix")==0)
		{
			int c;
			char postfix[3];
			ip = argv[i+1];
			if((pos_slash = ip.find("/",0))>0)
			{
				ip_pre = ip.substr(0,pos_slash);
				ip_range = 32 - atoi(ip.substr(pos_slash+1,ip.size()).c_str());
				long double ip_num = (int) pow(2.0,ip_range);
				cout<<"IP Num: "<<ip_num<<endl;
//				string lists[(int)ip_num];
				list = new string[(int)ip_num];
				list_count = (int)ip_num;
				pos_dot = -1;
				if(ip_range == 8)
				{
					for(int i=0;i<3;i++)
					{
						pos_dot = ip.find(".",pos_dot+1);			
					}		
					ip_pre = ip.substr(0,pos_dot);					
					for(int i=0;i<256;i++)
					{
						sprintf(postfix,"%d",i);
						list[c++] = ip_pre+"."+postfix;
					}
				}
				if(ip_range == 16)
				{
					for(int i=0;i<2;i++)
					{
						pos_dot = ip.find(".",pos_dot+1);			
					}		
					ip_pre = ip.substr(0,pos_dot);		
					cout<<"Pre::"<<ip_pre<<endl;			
					for(int i=0;i<256;i++)
					for(int k=0;k<256;k++)
					{
						sprintf(postfix,"%d.%d",i,k);
						list[c] = ip_pre+"."+postfix;
						cout<<"Post::"<<list[c++]<<endl;
					}				
				}
				if(ip_range == 24)
				{
					for(int i=0;i<1;i++)
					{
						pos_dot = ip.find(".",pos_dot+1);			
					}		
					ip_pre = ip.substr(0,pos_dot);		
					cout<<"Pre::"<<ip_pre<<endl;			
					for(int i=0;i<256;i++)
					for(int k=0;k<256;k++)
					for(int l=0;l<256;l++)
					{
						sprintf(postfix,"%d.%d.%d",i,k,l);
						list[c] = ip_pre+"."+postfix;
						cout<<"Post::"<<list[c++]<<endl;
					}				
				}
				if(ip_range == 32)
				{
					for(int i=0;i<256;i++)
					for(int k=0;k<256;k++)
					for(int l=0;l<256;l++)
					for(int m=0;m<256;m++)
					{
						sprintf(postfix,"%d.%d.%d.%d",i,k,l,m);
						list[c] = postfix;
						cout<<"Post::"<<list[c++]<<endl;
					}				
				}

//				for(int i=0;i<ip_num;i++)
//					cout<<list[i]<<endl;

				cout<<"Prefix: "<<ip_pre<<endl;
				cout<<"Range: "<<ip_num<<endl;
			}
			set_ip = true;
		}
		else if(arg.compare("--file")==0)
		{
			file = argv[i+1];
			list = new string[10];
			findFile = fopen(file.c_str(),"r");
			if(findFile != NULL)
			{
				fclose(findFile);
				sample.open(file.c_str());
				if(sample.is_open())
				{
				//	cout<<"Hello"<<endl;
					int i = 0;
					while(! sample.eof())
					{
						getline(sample,ip_line);
						list[i] = ip_line;
				//		cout<<"sample found: "<<ip_line<<endl;
					}
				}
				sample.close();
			}
			set_ip = true;
		}
		else if(arg.compare("--scan")==0)
		{
			pi = 0;				
			scan = argv[i+1];
			if(((pos_comma = scan.find(",",0))>0))
			{
				comma = -1;
				while(pos_comma>0)
				{
					scan_1 = scan.substr(comma+1,(pos_comma-comma-1));	
					scan_list[pi] = scan_1;
				//	cout<<"scan_1 inside main::::"<<scan_1<<endl;
					pi++;
					comma = pos_comma;
					pos_comma = scan.find(",",pos_comma+1);
//					cout<<pos_comma<<endl;
				}
				scan_2 = scan.substr(comma+1,scan.size()-(comma+1));	
				//	cout<<"scan_2::::"<<scan_2<<endl;			
				scan_list[pi] = scan_2;
				//for(int i=0;i<=pi;i++)
				//	cout<<"scan list inside main ::"<<scan_list[i]<<endl;				
			}
			else
			{
				scan_list[0] = scan;
			}
//			cout<<"SCAN: "<<scan_list[0]<<endl;
		}

	else if(arg.compare("--protocol-range")==0)
		{
			p_range = argv[i+1];
			if((pos_dash = p_range.find("-",0))>0)
			{
				proto_r1 = atoi(p_range.substr(0,pos_dash).c_str());	
				cout<<proto_r1<<endl;			
				proto_r2 = atoi(p_range.substr(pos_dash+1,p_range.size()-(pos_dash+1)).c_str());	
				cout<<proto_r2<<endl;			
				for(int i=0;i<(proto_r2-proto_r1+1);i++)
				{
					protocols[i] = proto_r1 + i;
					proto_count++;
//					cout<<protocols[i]<<endl;
				}
			}
			else
			{
				protocols[0] = atoi(p_range.substr(0,p_range.size()).c_str());
				proto_count++;
//					cout<<protocols[0]<<endl;
			}
							
		}


	}


	if(set_ip == false)
	{
		cout<<"IP not set"<<endl;
		exit(1);
	}
	if(set_port == false)
	{
		for(int i=0;i<1024;i++)
		{
			ports[i] = i+1;
			port_count=port_count+1;
			//cout<<"ports::"<<ports[i]<<endl;
		}
	}
//cout<<"sizeof list:::"<<sizeof(list)/sizeof(string)<<endl;
//cout<<"sizeof scan_list:::"<<sizeof(scan_list)/sizeof(string)<<endl;
//cout<<"pi:::"<<pi<<endl;

//build the queue
//cout<<sizeof(list)/sizeof(string)<<endl;
//cout<<sizeof(ports)/sizeof(int)<<endl;



	getifaddrs(&localAddr);
	for(ifaddrs *lA = localAddr; lA !=NULL; lA = lA->ifa_next)
	{
		conName = lA->ifa_name;		
		if(conName.compare("eth0")==0)
		{
			if(lA->ifa_addr->sa_family==AF_INET)
			{
				inet_ntop(AF_INET, &((sockaddr_in *)lA->ifa_addr)->sin_addr, source_ipp, INET_ADDRSTRLEN);
			}
		}
	}
	source_ip = source_ipp;

//cout<<"PI::"<<pi<<endl;

for(int i=0; i< list_count;i++)
{


for(int j=0;j<port_count;j++)
{

for(int k=0;k<=pi;k++)
{
string s="";
ostringstream convert; 
//cout<<"i::"<<list[i]<<endl;
//cout<<"j::"<<ports[j]<<endl;
s.append(list[i]);
//cout<<"s::"<<s<<endl;
s.append("|");
convert << ports[j];      
s.append(convert.str());
s.append("|");
s.append(scan_list[k]);
char * ptr1=new char[s.size()+1];
ptr1[s.size()]=0;
memcpy(ptr1,s.c_str(),s.size());
q.push(ptr1);
//cout<<"s::"<<s<<endl;
s="";
queue_size++;
}
}
}
//cout<<"Size::"<<queue_size<<endl;
/*string x;
while(!q.empty())
{
x=q.front();
	cout<<"x:::"<<x<<endl;
	q.pop();
}
*/


// Part 2
	if(pcap_findalldevs(&dev, errbuf))
	{
		cout<<"Cannot find devices"<<endl;
		exit(1);
	}
//	cout<<"Opening device"<<endl;
	dev_name = "eth0";
	recv_handle = pcap_open_live(dev_name.c_str() , 65535 , 1 , 1500 , errbuf);
	if(recv_handle == NULL)
	{
		cout<<"Device cannot be opened"<<endl;
		exit(1);
	}

	if((sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
	{
		//socket creation failed, may be because of non-root privileges
		cerr<<"Failed to create socket";
		exit(1);
	}

//cout<<"sockfd in main::::"<<sockfd;
	if (pcap_lookupnet(dev_name.c_str(), &net, &mask, errbuf) == -1) 
	{
		cout<<"Error setting net mask"<<endl;
		net = 0;
		mask = 0;
	}
	if (pcap_compile(recv_handle, &fp, filter_exp, 0, net) == -1) 
	{
		cout<<"Compile error"<<endl;
		return(2);
	}
	if (pcap_setfilter(recv_handle, &fp) == -1) 
	{
		cout<<"Compile error"<<endl;
		return(2);
	}
	//this loop will work till speedup right now hardcoded to 2
	for(int i=0;i<num_threads;i++)
			{
	
	//dfm[i].sockfd=sockfd;
	//cout<<"dfm[i].x:::"<<dfm[i].x<<endl;
	//q.pop();
	
//			cout<<"i="<<i<<endl;
	      		count=pthread_create(&thread_id[i], NULL, call_func_scan, (void *)&dfm[i]);
			pthread_mutex_lock( &mutex1 );				
			cout<<"thread_id ::"<<thread_id<<endl;
			//cout<<"count::::"<<count<<endl;
	//cout<<"sockfd while creating threads::::"<<dfm[i].sockfd;
		 pthread_mutex_unlock( &mutex1 );	
		}

	for(int i=0;i<num_threads;i++)
			{
				//cout<<"thread_id[i]::::"<<thread_id[i]<<endl;
	     			pthread_join(thread_id[i], NULL);
			}

	//dfm[0].sin=sin;
	// code form here cut for new function	





/*while(true)
{
	if(pcap_dispatch(recv_handle, 2, received_packet, NULL)==0)
		{
			if(timeout_var<3)
			{
			cout<<errbuf<<endl;
			timeout_var++;
			continue;
			}
			else
			{
			cout<<"No more packets received."<<endl;
			break;
			}
		}
      //  loop_var ++;
	//cout<<"sfskgfskfggf:::"<<loop_var<<endl;
}		
*/
/*bool loop=true;
int scan_type;
while(loop)
		{
			packet_sent = pcap_next(recv_handle, &header);
			if((scan_type=received_packet(NULL, &header, packet_sent, 0))!=0)
			{
//				cout<<"Scan::"<<scan_type<<endl;
			}
			packet_recv = pcap_next(recv_handle, &header);
			if(scan_type == 61 ||scan_type == 62 ||scan_type == 63 ||scan_type == 64 ||scan_type == 65)
			{
				if(received_packet(NULL, &header, packet_recv, scan_type)==0)
				{
//					cout<<"Done"<<endl;
					loop = false;
					break;
				}
			}
		}
*/
	cout<<"Ending port scanner"<<endl;
	delete[] list;
	pcap_close(recv_handle);
	return 0;
}

