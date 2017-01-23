/* Copyright (c) 2002 Gianni Tedesco
 * Released under the terms of the GNU GPL version 2
 * mmap() packet socket based packet sniffer
*/

#ifndef __linux__
#error "Are you loco? This is Linux only!"
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#define __USE_XOPEN
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <features.h>    /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>     /* the L2 protocols */
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */
#endif
#include <string.h>
#include <netinet/in.h>
//#include <asm-generic/system.h>
#include <signal.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h> // for ntoa error

#define SRC_IP 		“1.2.3.4”

#if 0
char *names[]={
	"<", /* incoming */
	"B", /* broadcast */
	"M", /* multicast */
	"P", /* promisc */
	">", /* outgoing */
};
#else
char *names[]={
	"Rx: ", /* incoming */
	"Bc: ", /* broadcast */
	"Mc: ", /* multicast */
	"Promise ", /* promisc */
	"Rx ", /* outgoing */
};
#endif

/*下边是以太网的协议格式 */
struct ethernet_header
{ 

	u_int8_t ether_dhost[6];  /*目的以太地址*/
	u_int8_t ether_shost[6];  /*源以太网地址*/
	u_int16_t ether_type;  /*以太网类型*/
};
/*ip地址格式*/
typedef u_int32_t in_addr_t;
struct ip_header
{
#ifdef WORKS_BIGENDIAN
	u_int8_t ip_version:4,  /*version:4*/
		 ip_header_length:4; /*IP协议首部长度*/
#else
	u_int8_t ip_header_length:4,
		 ip_version:4;
#endif
	u_int8_t ip_tos;   /*TOS服务质量*/
	u_int16_t ip_length;  /*总长度*/
	u_int16_t ip_id;   /*标识*/
	u_int16_t ip_off;   /*偏移*/
	u_int8_t ip_ttl;   /*生存时间*/
	u_int8_t ip_protocol;  /*协议类型*/
	u_int16_t ip_checksum;  /*校验和*/
	struct in_addr  ip_source_address; /*源IP*/
	struct in_addr  ip_destination_address; /*目的IP*/
};






int task_send(int num,int blocking, char* buf, int buf_len);
/** Print a buffer.
 *
 * @param buf to print
 * @param n number of bytes to print
 */
void buf_print(char *buf, int n){
    int i;
    for(i=0; i<n; i++){
        if( i % 16 == 0) printf("\n%04d: ", i);
        else if(i % 8 == 0) printf(" ");
        printf("%02x ", buf[i] & 0xff);
    }
    printf(" %04d\n", n);
}



// checksum function BSD Tahoe
unsigned short in_cksum(unsigned short *addr, int len)
{
        //hexdump(addr,len);

        int nleft = len;
        int sum = 0;
        unsigned short *w = addr;
        unsigned short answer = 0;

        while (nleft > 1) {
                sum += *w++;
                nleft -= 2;
        }

        if (nleft == 1) {
                *(unsigned char *) (&answer) = *(unsigned char *) w;
                sum += answer;
        }

        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        answer = ~sum;
        return (answer);
}

#define USHORT unsigned short
#define UCHAR unsigned char

USHORT ip_checksum(USHORT* buffer, int size)
{
    unsigned long cksum = 0;
    while(size>1)
    {
        cksum += *buffer++;
        size -= sizeof(USHORT);
    }
    if(size)
    {
        cksum += *(UCHAR*)buffer;
    }
    cksum = (cksum>>16) + (cksum&0xffff); 
    cksum += (cksum>>16); 
    return (USHORT)(~cksum);
}

int fd=-1;
char *map;
struct tpacket_req req; // for rx
struct iovec *ring;

struct tpacket_req s_packet_req; //for tx
volatile struct tpacket_hdr * ps_header_start;
volatile struct sockaddr_ll *ps_sockaddr = NULL;


void sigproc(int sig)
{
	struct tpacket_stats st;
	int len=sizeof(st);

	if (!getsockopt(fd,SOL_PACKET,PACKET_STATISTICS,(char *)&st,&len)) {
		fprintf(stderr, "recieved %u packets, dropped %u\n",
			st.tp_packets, st.tp_drops);
	}
	
	if ( map ) munmap(map, req.tp_block_size * req.tp_block_nr);
	if ( fd>=0 ) close(fd);
	if ( ring ) free(ring);

	exit(0);
}

static int c_packet_sz   = 1024;
static int c_packet_nb   = 4*64;

static int c_buffer_sz   = 4096;
static int c_buffer_nb   = 64;


/*下边实现IP数据包分析的函数定义ethernet_protocol_packet_callback*/
void ip_protocol_filter(const u_char* packet_content)
{
	struct ip_header *ip_protocol;   /*ip协议变量*/
	u_int  header_length;    /*长度*/
	u_int  offset;     /*偏移*/
	u_char  tos;     /*服务质量*/
	u_int16_t checksum;    /*校验和*/
	ip_protocol=(struct ip_header*) (packet_content+14);
	/*获得ip数据包的内容去掉以太头部*/

	checksum=ntohs(ip_protocol->ip_checksum);  /*获得校验和*/
	header_length=ip_protocol->ip_header_length*4; /*获得长度*/
	tos=ip_protocol->ip_tos;    /*获得tos*/
	offset=ntohs(ip_protocol->ip_off);   /*获得偏移量*/
	printf("***************IP Protocol network layer***************\n \n");
	printf("IP Version :%d\n",ip_protocol->ip_version);
	printf("Header length :%d\n",header_length);
	printf("Tos :%d\n",tos);
	printf("Total length:%d\n",ntohs(ip_protocol->ip_length));/*获得总长度*/
	printf("Identification:%d\n",ntohs(ip_protocol->ip_id));  /*获得标识*/
	printf("Offset:%d\n",(offset&0x1fff)*8);    /**/
	printf("TTL:%d\n",ip_protocol->ip_ttl);     /*获得ttl*/ 
	printf("protocol:%d\n",ip_protocol->ip_protocol);         /*获得协议类型*/

	printf("Header checksum:%d\n",checksum);
	printf("Source address:%s\n",inet_ntoa(ip_protocol->ip_source_address));          /*
											     获得源ip地址*/
	printf("Destinastion address :%s\n",inet_ntoa(ip_protocol->ip_destination_address));
	/*获得目的ip地址*/
	switch(ip_protocol->ip_protocol)
	{
		case 6 :printf("The Transport Layer Protocol is TCP#####################################\n");
			//tcp_protocol_packet_callback(argument,packet_header,packet_content);

			break; /*协议类型是6代表TCP*/
		case 17:printf("The Transport Layer Protocol is  UDP\n");break;/*17代表UDP*/
		case 1:
			printf("The Transport Layer Protocol is ICMP\n");
			
			icmp_send(10,1,packet_content,ntohs(ip_protocol->ip_length));
			break;/*代表ICMP*/
		case 2:printf("The Transport Layer Protocol is IGMP\n");break;/*代表IGMP*/
		default :break;
	}

}
void ethernet_filter(const u_char* packet_content)
{
	u_short ethernet_type;     /*以太网协议类型*/
	struct ethernet_header *ethernet_protocol;  /*以太网协议变量*/
	u_char *mac_string;
	static int packet_number=1;

	printf("*******************************************************************************\n");
	printf("The %d ip packet is captured,\n",packet_number);
	printf("**********ethernet protocol (link Layer)*******************\n");
	ethernet_protocol =(struct ethernet_header *) packet_content;  /*获得一太网协议数据内容*/
	printf("Ethernet type is :\n");
	ethernet_type=ntohs(ethernet_protocol->ether_type);
	/*获得以太网类型*/
	printf("%04x\n",ethernet_type);
	switch(ethernet_type)            /*判断以太网类型的值*/
	{
		case 0x0800 :  printf("The network layer is ip protocol\n");break;
		case 0x0806 :  printf("The network layer is ARP protocol\n");break;
		case 0x8035 :  printf("The network layer is RARP protocol\n");break;
		default: break;
	}
	if(ethernet_type != 0x0800)
	{
		return;
	}	
	printf("Mac souce address is :\n");
	mac_string=ethernet_protocol->ether_shost;
	printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));

	/*获得以太网地址*/

	printf("Mac Destination Address is :\n");
	mac_string=ethernet_protocol->ether_dhost;
	printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));

	/*获得目的端口地址*/

	switch (ethernet_type)
	{case 0x0800:   ip_protocol_filter(packet_content);break;
		/*如果上层是ip协议,就调用分析ip协议的函数对ip包进行贩治*/ 
		default :break;
	}

	packet_number++;
}

/* This task will call send() procedure */
int icmp_send(int num,int blocking, const char* packet_content, int buf_len) {
        int i=0;
	int ec_send=0;
        static int total=0;
	char buf[2048]={0};
        //int blocking = (int) arg;

	u_char *mac_string;
        u_short ethernet_type;     /*以太网协议类型*/
        struct ethernet_header *ethernet_protocol;  /*以太网协议变量*/
        struct ethernet_header *ethernet_protocol2;  /*以太网协议变量*/

        struct ip_header *ip_protocol;   /*ip协议变量*/
        struct ip_header *ip_protocol2;   /*ip协议变量*/
        u_int  header_length;    /*长度*/
        u_int  offset;     /*偏移*/
        u_char  tos;     /*服务质量*/
        u_int16_t checksum;    /*校验和*/

        ethernet_protocol =(struct ethernet_header *) packet_content;  /*获得一太网协议数据内容*/
        ethernet_type=ntohs(ethernet_protocol->ether_type);
	// ip
        if(ethernet_type != 0x0800)
        {       
                return;
	}
        ip_protocol=(struct ip_header*) (packet_content+14);
        /*获得ip数据包的内容去掉以太头部*/

        checksum=ntohs(ip_protocol->ip_checksum);  /*获得校验和*/
        header_length=ip_protocol->ip_header_length*4; /*获得长度*/
        tos=ip_protocol->ip_tos;    /*获得tos*/
        offset=ntohs(ip_protocol->ip_off);   /*获得偏移量*/
        
	//icmp
        if(ip_protocol->ip_protocol !=0x1)
        {
		return;
	}
     
	
	memcpy(buf,packet_content,buf_len);
	
	printf("***************IP Protocol network layer***************\n \n");
        printf("IP Version :%d\n",ip_protocol->ip_version);
        printf("Header length :%d\n",header_length);
        printf("Tos :%d\n",tos);
        printf("Total length:%d\n",ntohs(ip_protocol->ip_length));/*获得总长度*/
        printf("Identification:%d\n",ntohs(ip_protocol->ip_id));  /*获得标识*/
        printf("Offset:%d\n",(offset&0x1fff)*8);    /**/
        printf("TTL:%d\n",ip_protocol->ip_ttl);     /*获得ttl*/
        printf("protocol:%d\n",ip_protocol->ip_protocol);         /*获得协议类型*/

        printf("Header checksum:%d\n",checksum);
        printf("Source address:%s\n",inet_ntoa(ip_protocol->ip_source_address));          /*
                                                                                             获得源ip地址*/
        printf("Destinastion address :%s\n",inet_ntoa(ip_protocol->ip_destination_address));

	//exchange mac
        printf("old Smac:");
        mac_string=ethernet_protocol->ether_shost;
        printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));

        /*获得以太网地址*/

        printf("old Dmac:");
        mac_string=ethernet_protocol->ether_dhost;
        printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));


        ethernet_protocol2 =(struct ethernet_header *)buf;  /*获得一太网协议数据内容*/

        ip_protocol2=(struct ip_header*) (buf+14);
        /*获得ip数据包的内容去掉以太头部*/
	memcpy(ethernet_protocol2->ether_dhost,ethernet_protocol->ether_shost,6);
	memcpy(ethernet_protocol2->ether_shost,ethernet_protocol->ether_dhost,6);
        printf("new Smac:");
        mac_string=ethernet_protocol2->ether_shost;
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
        
        /*获得以太网地址*/

        printf("new Dmac:");
        mac_string=ethernet_protocol2->ether_dhost;
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));


	//modify sip
	//ip_protocol2->ip_source_address = 0；
	inet_aton("1.2.3.4",&ip_protocol2->ip_source_address);
	inet_aton("103.77.56.27",&ip_protocol2->ip_destination_address);
        printf("new Source address:%s\n",inet_ntoa(ip_protocol2->ip_source_address));
	//update checksum
	ip_protocol2->ip_checksum = 0;
	//ip_protocol2->ip_checksum = in_cksum((unsigned short *)ip_protocol2, header_length);
        printf("new checksum=0x%x\n",ip_protocol2->ip_checksum);
	ip_protocol2->ip_checksum = ip_checksum((unsigned short *)ip_protocol2, header_length);
        printf("new 1 checksum=0x%x\n",ip_protocol2->ip_checksum);
	//ip_protocol2->ip_checksum = htons(ip_protocol2->ip_checksum);
        printf("new 2 checksum=0x%x\n",ip_protocol2->ip_checksum);
	//send out
        do
        {
                /* send all buffers with TP_STATUS_SEND_REQUEST */
                /* Wait end of transfer */
                //printf("send() start\n");
                ec_send = sendto(fd,
                                buf,
                                buf_len,
                                (blocking? 0 : MSG_DONTWAIT),
                                (struct sockaddr *) ps_sockaddr,
                                sizeof(struct sockaddr_ll));


                if(ec_send < 0) {
                	printf("send() end (ec=%d)\n",ec_send);
                        perror("send");
                        break;
                }
                else if ( ec_send == 0 ) {
                        /* nothing to do => schedule : useful if no SMP */
                        usleep(0);
                }
                else {
                        i++;
                        total += ec_send;
                        printf("send %d packets (+%d bytes)\n",total, ec_send);
                        fflush(0);
                }

        } while(i<num);

        //if(blocking) printf("end of task send()\n");
        printf("end of send(ec=%x)\n", ec_send);
        return ec_send;
}



/* This task will call send() procedure */
int task_send(int num,int blocking, char* buf, int buf_len) {
	int i,ec_send;
	int total=0;
	//int blocking = (int) arg;

	printf("start send() thread\n");

	do
	{
		/* send all buffers with TP_STATUS_SEND_REQUEST */
		/* Wait end of transfer */
		printf("send() start\n");
		ec_send = sendto(fd,
				buf,
				buf_len,
				(blocking? 0 : MSG_DONTWAIT),
				(struct sockaddr *) ps_sockaddr,
				sizeof(struct sockaddr_ll));

		printf("send() end (ec=%d)\n",ec_send);

		if(ec_send < 0) {
			perror("send");
			break;
		}
		else if ( ec_send == 0 ) {
			/* nothing to do => schedule : useful if no SMP */
			usleep(0);
		}
		else {
			i++;
			total += ec_send;
			printf("send %d packets (+%d bytes)\n",total, ec_send);
			fflush(0);
		}

	} while(i<num);

	//if(blocking) printf("end of task send()\n");
	printf("end of task send(ec=%x)\n", ec_send);
#if 0
	/* check buffer */
	int i_nb_error = 0;
	for(i=0; i<c_buffer_nb; i++)
	{
		struct tpacket_hdr * ps_header;
		ps_header = ((struct tpacket_hdr *)((void *)ps_header_start + (c_buffer_sz*i)));
		switch((volatile uint32_t)ps_header->tp_status)
		{
			case TP_STATUS_SEND_REQUEST:
				printf("A frame has not been sent %p\n",ps_header);
				i_nb_error++;
				break;

			case TP_STATUS_LOSING:
				printf("An error has occured during transfer\n");
				i_nb_error++;
				break;

			default:
				break;
		}

	}	
#endif
	return ec_send;
}


int main ( int argc, char **argv ) 
{
	struct pollfd pfd;
	struct sockaddr_ll addr;
	int i;

	struct ifreq s_ifr; /* points to one interface returned from ioctl */
	int i_ifindex, ec;
	unsigned int size;
	struct sockaddr_ll my_addr, peer_addr;

	signal(SIGINT, sigproc);

	/* Open the packet socket */
	//if ( (fd=socket(PF_PACKET, SOCK_DGRAM, 0))<0 ) {
	//fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	//fd = socket(PF_PACKET, SOCK_DGRAM, htons (ETH_P_ARP));
	if ( (fd=socket(PF_PACKET, SOCK_RAW, htons (ETH_P_ALL)))<0 ) {
		perror("socket()");
		return 1;
	}

	/* Setup the fd for mmap() ring buffer */
	req.tp_block_size=4096;
	req.tp_frame_size=1024;
	req.tp_block_nr=64;
	req.tp_frame_nr=4*64;
	if ( (setsockopt(fd,SOL_PACKET,	PACKET_RX_RING,	(char *)&req, sizeof(req))) != 0 ) {
		perror("Rx setsockopt()");
		close(fd);
		return 1;
	};


	/* tx init */
	/* prepare Tx ring request */

	s_packet_req.tp_block_size = 4096;
	s_packet_req.tp_frame_size = 1024;
	s_packet_req.tp_block_nr = 64;
	s_packet_req.tp_frame_nr = 4*64;


	/* mmap() the sucker */
	map=mmap(NULL,
		req.tp_block_size * req.tp_block_nr,
		PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED, fd, 0);
	if ( map==MAP_FAILED ) {
		perror("Rx mmap()");
		close(fd);
		return 1;
	}

	/* Setup our ringbuffer */
	ring=malloc(req.tp_frame_nr * sizeof(struct iovec));
	for(i=0; i<req.tp_frame_nr; i++) {
		ring[i].iov_base=(void *)((long)map)+(i*req.tp_frame_size);
		ring[i].iov_len=req.tp_frame_size;
	}
#if 0

	/* calculate memory to mmap in the kernel */
	size = s_packet_req.tp_block_size * s_packet_req.tp_block_nr;
#if 0 
	/* send TX ring request */
	if (setsockopt(fd, SOL_PACKET, PACKET_TX_RING, (char *)&s_packet_req, sizeof(s_packet_req))<0)
	{
		perror("Tx setsockopt: PACKET_TX_RING");
		close(fd);
		return 1;
	}
#endif
	/* mmap Tx ring buffers memory */
	ps_header_start = mmap(0, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (ps_header_start == (void*)-1)
	{
		perror("Tx mmap");
		return EXIT_FAILURE;
	}
#endif

#if 0
	/* bind the packet socket */
	memset(&addr, 0, sizeof(addr));
	addr.sll_family=AF_PACKET;
	//addr.sll_protocol=htons(0x03);  //ETH_P_ARP
	//addr.sll_protocol=htons(ETH_P_ARP);  //ETH_P_ARP
	//addr.sll_protocol=htons(ETH_P_ALL);  //ETH_P_ARP
	addr.sll_protocol=htons(ETH_P_IP);  //ip 
	//addr.sll_ifindex=0;
	addr.sll_ifindex=0;
	addr.sll_hatype=0;
	addr.sll_pkttype=0;
	addr.sll_halen=0;
	if ( bind(fd, (struct sockaddr *)&addr, sizeof(addr)) ) {
		munmap(map, req.tp_block_size * req.tp_block_nr);
		perror("bind()");
		close(fd);
		return 1;
	}
#else
	/* initialize interface struct */
	strncpy (s_ifr.ifr_name, argv[1], sizeof(s_ifr.ifr_name));
	printf("get dev: %s\n",s_ifr.ifr_name); 
	/* Get the broad cast address */
	ec = ioctl(fd, SIOCGIFINDEX, &s_ifr);
	if(ec == -1)
	{
		perror("iotcl");
		close(fd);
		return 1;
	}
	/* update with interface index */
	i_ifindex = s_ifr.ifr_ifindex;
  
	printf("get dev index: %d\n",i_ifindex); 
	/* set sockaddr info */
	memset(&my_addr, 0, sizeof(struct sockaddr_ll));
	// all pkt
	//my_addr.sll_family = PF_PACKET;
	//my_addr.sll_protocol=htons(ETH_P_ALL);  //ETH_P_ARP
	// ip pkt
	my_addr.sll_family = AF_PACKET;
	my_addr.sll_protocol=htons(ETH_P_IP);  //ip 
	my_addr.sll_ifindex = i_ifindex;
        my_addr.sll_hatype=0;
        my_addr.sll_pkttype=0;
        my_addr.sll_halen=0;
	/* bind port */
	if (bind(fd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr_ll)) == -1)
	{
		munmap(map, req.tp_block_size * req.tp_block_nr);
		perror("bind()");
		close(fd);
		return 1;
	}

	/* fill peer sockaddr for SOCK_DGRAM */
	if (1)
	{
		char dstaddr[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff};
		//peer_addr.sll_family = AF_PACKET;
		//peer_addr.sll_protocol = htons(ETH_P_IP);
		peer_addr.sll_family = PF_PACKET;
		peer_addr.sll_protocol = htons(ETH_P_ALL);
		peer_addr.sll_ifindex = i_ifindex;
		peer_addr.sll_halen = ETH_ALEN;
		memcpy(&peer_addr.sll_addr, dstaddr, ETH_ALEN);
		ps_sockaddr = &peer_addr;
	}
#endif

	int j=0;
	for(i=0;;) {
		while((*(unsigned long*)ring[i].iov_base) && (j<10)) {
			struct tpacket_hdr *h=ring[i].iov_base;
			struct sockaddr_ll *sll=(void *)h + TPACKET_ALIGN(sizeof(*h));
			unsigned char *bp=(unsigned char *)h + h->tp_mac;
			//j++;
			/* print promise intf */
			//if(sll->sll_pkttype==3)
			//if(sll->sll_pkttype==0)
			{
/*
				printf("%u.%.6u: if%u type=%d %s %u bytes\n",
				h->tp_sec, h->tp_usec,
				sll->sll_ifindex,sll->sll_pkttype,
				names[sll->sll_pkttype],
				h->tp_len);
				
				// dump skb
				buf_print((char *)bp,(int)h->tp_len);
				ethernet_filter((const u_char*)bp);
*/
				/* send out */
				icmp_send(1,1,(const u_char*)bp,(int)h->tp_len);
				/* send all buffers with TP_STATUS_SEND_REQUEST */
				/* Don't wait end of transfer */
				//task_send(10,1, (char *)bp,(int)h->tp_len);
				
			}
			/* tell the kernel this packet is done with */
			h->tp_status=0;
			//mb(); /* memory barrier */
			
			i=(i==req.tp_frame_nr-1) ? 0 : i+1;
		}

		/* Sleep when nothings happening */
		pfd.fd=fd;
		pfd.events=POLLIN|POLLERR;
		pfd.revents=0;
		poll(&pfd, 1, -1);
	}
	
	return 0;
}

