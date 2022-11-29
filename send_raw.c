#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include "raw.h"

// to get ip
#include<errno.h>  
#include<netdb.h>
#include<ifaddrs.h>
#include<unistd.h>
 
void *getip(char host[4]);

u_int32_t packet_xid=0;
 
char this_mac[6];
char bcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char dst_mac[6] =   {0x00, 0x00, 0x00, 0x22, 0x22, 0x22};
char src_mac[6] =   {0x00, 0x00, 0x00, 0x33, 0x33, 0x33};
 
uint8_t broadcast_address[4] = {255, 255, 255, 255};
uint8_t client_init_address[4] = {0, 0, 0, 0};
uint8_t this_address[4] = {192, 0, 2, 1};
uint8_t this_subnet_mask[4] = {255, 255, 255, 0};
char this_ip[13] = "10.130.243.63";
char spoofing_ip[13] = "192.0.2.1"; // ((in_addr_t)0x010200c0);
 
int main(int argc, char *argv[])
{
	//  getip(this_address);
	memcpy(this_address, this_address, 4);

	struct ifreq if_idx, if_mac, ifopts;
	char ifName[IFNAMSIZ];

	struct sockaddr_ll socket_address;
	int sockfd, numbytes, size = 100;

	uint8_t raw_buffer[ETH_LEN];
	bzero(raw_buffer, ETH_LEN);
	struct eth_frame_s *raw = (struct eth_frame_s *)&raw_buffer;

	struct dhcp_hdr_s *dhcp = (struct dhcp_hdr_s *)&raw_buffer[sizeof(struct eth_hdr_s)+sizeof(struct ip_hdr_s)+sizeof(struct udp_hdr_s)];

	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");

	/* Set interface to promiscuous mode */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

	/* Get the index of the interface */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);

	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");

	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;

	/* Get the MAC address of the interface */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);

	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR");

	memcpy(this_mac, if_mac.ifr_hwaddr.sa_data, 6);

	/* End of configuration. Now we can send data using raw sockets. */
	/* To send data (in this case we will cook an ARP packet and broadcast it =])... */
	/* fill the Ethernet frame header */
	memcpy(raw->ethernet.dst_addr, bcast_mac, 6);
	memcpy(raw->ethernet.src_addr, src_mac, 6);
	raw->ethernet.eth_type = htons(ETH_P_IP);

	/* Fill IP header data. Fill all fields and a zeroed CRC field, then update the CRC! */
	raw->ip.ver = 0x45;
	raw->ip.tos = 0x00;
	raw->ip.len = htons(sizeof(struct ip_hdr_s) + sizeof(struct udp_hdr_s) + sizeof(struct dhcp_hdr_s));
	raw->ip.id = htons(0x00);
	raw->ip.off = htons(0x00);
	raw->ip.ttl = 255;
	raw->ip.proto = 17;
	raw->ip.sum = htons(0x0000);
	memcpy(raw->ip.src, this_address, 4);
	memcpy(raw->ip.dst, client_init_address, 4);

	/* fill source and destination addresses */
	/* calculate the IP checksum */
	/* raw->ip.sum = htons((~ipchksum((uint8_t *)&raw->ip) & 0xffff)); */
	/* fill payload data */
	raw->udp.dst_port = htons(68); // htons is for 16 bits
	raw->udp.src_port = htons(67);
	raw->udp.udp_len = htons(sizeof(struct dhcp_hdr_s));
	raw->udp.udp_chksum = htons(0);

    /* our hardware address */
    // memcpy(dhcp->chaddr, client_hardware_address, ETHERNET_HARDWARE_ADDRESS_LENGTH);
	// send_dhcp_offer(dhcp);
	send_dhcp_ack(dhcp);

	/* fill dhcp --offer */
//	raw->dhcp.op = 6; // ta salvando em hlen (hardware address len)
//	((int *)raw)[sizeof(struct eth_hdr_s)+sizeof(struct ip_hdr_s)+sizeof(struct udp_hdr_s)+1] = 6;
	// usar p/ uint8 -> uint32 v4[0] | (v4[1] << 8) | (v4[2] << 16) | (v4[3] << 24);
	//  raw->dhcp.htype = 0x05; // ta alterando o hops
	//  raw->dhcp.hlen = 20; // alterando 1 dos numeros de transaction ID
	//  raw->dhcp.hops = 0;
	//  raw->dhcp.xid = htonl(0x49ee5a54); // aleatorio mas sempre igual em 1 transaçao - salvando os 4 mais significativos no 4 menos significativos
	//   raw->dhcp.secs = htons(3); // ta salvando em flag
	//  raw->dhcp.flags = htons(0x0);
	//  raw->dhcp.options[1] = 4;
	//  memcpy(raw->dhcp.ciaddr, client_init_address, 4);
	//  memcpy(raw->dhcp.yiaddr, client_init_address, 4);
	//  memcpy(raw->dhcp.giaddr, client_init_address, 4);
	//  memcpy(raw->dhcp.chaddr, dst_mac, 6);
	//raw->dhcp.options[0] = 255;

	/* Send it.. */
	memcpy(socket_address.sll_addr, dst_mac, 6);
	
	if (sendto(sockfd, raw_buffer, sizeof(struct eth_hdr_s) + sizeof(struct ip_hdr_s) + sizeof(struct udp_hdr_s) + sizeof(struct dhcp_hdr_s), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		printf("Send failed\n");

	return 0;
}
 

void send_dhcp_offer(struct dhcp_hdr_s *dhcp){
	dhcp->op = 6;
	dhcp->htype = 0x05;

	/* boot request flag (backward compatible with BOOTP servers) */
    dhcp->op=BOOTREPLY;

    /* hardware address type */
    dhcp->htype=ETHERNET_HARDWARE_ADDRESS;

    /* length of our hardware address */
    dhcp->hlen=ETHERNET_HARDWARE_ADDRESS_LENGTH;

    dhcp->hops=0;

    /* shold get the xid from CLIENT DISCOVER */
    packet_xid=123;
    dhcp->xid=htonl(packet_xid);

    /**** WHAT THE HECK IS UP WITH THIS?!?  IF I DON'T MAKE THIS CALL, ONLY ONE SERVER RESPONSE IS PROCESSED!!!! ****/
    /* downright bizzarre... */
    ntohl(dhcp->xid);

    /*dhcp->secs=htons(65535);*/
    dhcp->secs=0xFF;

    /* tell server it should broadcast its response */ 
    dhcp->flags=htons(DHCP_UNICAST_FLAG);

    /* Set client address*/
    inet_aton("0.0.0.0", &dhcp->ciaddr);

    /* Set sender (server) address*/
    inet_aton(this_ip, &dhcp->yiaddr);

    struct sockaddr_in sa;
    char buffer[INET_ADDRSTRLEN];
    inet_ntop( AF_INET, &dhcp->yiaddr, buffer, sizeof( buffer ));

    /* Set next server address*/
    inet_aton("0.0.0.0", &dhcp->siaddr);

    /* Set relay agent address*/
    inet_aton("0.0.0.0", &dhcp->giaddr);

	/* fill options*/

	/* first four bytes of options field is magic cookie (as per RFC 2132) */
    dhcp->options[0]='\x63';
    dhcp->options[1]='\x82';
    dhcp->options[2]='\x53';
    dhcp->options[3]='\x63';

    /* DHCP message type is embedded in options field */
    dhcp->options[4]=DHCP_OPTION_MESSAGE_TYPE;    /* DHCP message type option identifier */
    dhcp->options[5]='\x01';               /* DHCP message option length in bytes */
    dhcp->options[6]=DHCPOFFER;

    struct in_addr *server_ip = malloc(sizeof (struct in_addr));
    inet_aton(this_ip, server_ip);

    // fill dhcp subnet mask (1)
    dhcp->options[7]  = 1;
    dhcp->options[8]  = 4;
    dhcp->options[9]  = this_subnet_mask[0];
    dhcp->options[10] = this_subnet_mask[1];
    dhcp->options[11] = this_subnet_mask[2];
    dhcp->options[12] = this_subnet_mask[3];

    // fill dhcp renewal time (58)
    dhcp->options[13] = 58;
    dhcp->options[14] = 4;
    dhcp->options[15] = 0;
    dhcp->options[16] = 1;
    dhcp->options[17] = 56;
    dhcp->options[18] = 128;

    // fill dhcp rebinding time (59)
    dhcp->options[19] = 59;
    dhcp->options[20] = 4;
    dhcp->options[21] = 0;
    dhcp->options[22] = 1;
    dhcp->options[23] = 56;
    dhcp->options[24] = 128;
    
    // fill dhcp lease time (51)
    dhcp->options[25] = 51;
    dhcp->options[26] = 4;
    dhcp->options[27] = 0;
    dhcp->options[28] = 1;
    dhcp->options[29] = 56;
    dhcp->options[30] = 128;

    // fill dhcp server identifier    
    dhcp->options[31] = 54;//0xff; 
    dhcp->options[32] = 4; 
    dhcp->options[33] = server_ip->s_addr; 
    dhcp->options[34] = server_ip->s_addr >> 8;
    dhcp->options[35] = server_ip->s_addr >> 16;
    dhcp->options[36] = server_ip->s_addr >> 24;
     
    // fill dhcp router
    dhcp->options[37] = 3;
    dhcp->options[38] = 4;
    dhcp->options[39] = server_ip->s_addr;
    dhcp->options[40] = server_ip->s_addr >> 8;
    dhcp->options[41] = server_ip->s_addr >> 16;
    dhcp->options[42] = server_ip->s_addr >> 24;

    // fill dhcp dns
    // se usar size ([32]) como 8 da para enviar 2 dns servers
    dhcp->options[43] = 6;
    dhcp->options[44] = 4;
    dhcp->options[45] = server_ip->s_addr;
    dhcp->options[46] = server_ip->s_addr >> 8;
    dhcp->options[47] = server_ip->s_addr >> 16;
    dhcp->options[48] = server_ip->s_addr >> 24;

    // fill dhcp broadcast
    dhcp->options[49] = 28;
    dhcp->options[50] = 4;
    dhcp->options[51] = 255;
    dhcp->options[52] = 255;
    dhcp->options[53] = 255;
    dhcp->options[54] = 255;

    // fill end
    dhcp->options[255] = 255;
}



void send_dhcp_ack(struct dhcp_hdr_s *dhcp){
/* boot request flag (backward compatible with BOOTP servers) */
    dhcp->op=BOOTREPLY;

    /* hardware address type */
    dhcp->htype=ETHERNET_HARDWARE_ADDRESS;

    /* length of our hardware address */
    dhcp->hlen=ETHERNET_HARDWARE_ADDRESS_LENGTH;

    dhcp->hops=0;

    /* shold get the xid from CLIENT DISCOVER */
    packet_xid=123;
    dhcp->xid=htonl(packet_xid);

    /**** WHAT THE HECK IS UP WITH THIS?!?  IF I DON'T MAKE THIS CALL, ONLY ONE SERVER RESPONSE IS PROCESSED!!!! ****/
    /* downright bizzarre... */
    ntohl(dhcp->xid);

    /*dhcp->secs=htons(65535);*/
    dhcp->secs=0xFF;

    /* tell server it should broadcast its response */ 
    dhcp->flags=htons(DHCP_UNICAST_FLAG);

    /* Set client address*/
    inet_aton("0.0.0.0", &dhcp->ciaddr);

    /* Set sender (server) address*/
    inet_aton(this_ip, &dhcp->yiaddr);

    struct sockaddr_in sa;
    char buffer[INET_ADDRSTRLEN];
    inet_ntop( AF_INET, &dhcp->yiaddr, buffer, sizeof( buffer ));

    /* Set next server address*/
    inet_aton("0.0.0.0", &dhcp->siaddr);

    /* Set relay agent address*/
    inet_aton("0.0.0.0", &dhcp->giaddr);

    /* our hardware address */
    // memcpy(dhcp->chaddr, client_hardware_address, ETHERNET_HARDWARE_ADDRESS_LENGTH);

    /* first four bytes of options field is magic cookie (as per RFC 2132) */
    dhcp->options[0]='\x63';
    dhcp->options[1]='\x82';
    dhcp->options[2]='\x53';
    dhcp->options[3]='\x63';

    /* DHCP message type is embedded in options field */
    dhcp->options[4]=DHCP_OPTION_MESSAGE_TYPE;    /* DHCP message type option identifier */
    dhcp->options[5]='\x01';               /* DHCP message option length in bytes */
    dhcp->options[6]=DHCPACK;

    struct in_addr *server_ip = malloc(sizeof (struct in_addr));
    inet_aton(this_ip, server_ip);

    // fill dhcp renewal time (58)
    dhcp->options[7]  = 58; 
    dhcp->options[8]  = 4; 
    dhcp->options[9]  = 0; 
    dhcp->options[10] = 1; 
    dhcp->options[11] = 56; 
    dhcp->options[12] = 128; 

    // fill dhcp rebinding time (59)
    dhcp->options[13] = 59;
    dhcp->options[14] = 4;
    dhcp->options[15] = 0;
    dhcp->options[16] = 1;
    dhcp->options[17] = 56;
    dhcp->options[18] = 128;

    // fill dhcp lease time (51)
    dhcp->options[19] = 51;
    dhcp->options[20] = 4;
    dhcp->options[21] = 0;
    dhcp->options[22] = 1;
    dhcp->options[23] = 56;
    dhcp->options[24] = 128;
    
    // fill dhcp server identifier (54)
    dhcp->options[25] = 54;
    dhcp->options[26] = 4;
    dhcp->options[27] = server_ip->s_addr; 
    dhcp->options[28] = server_ip->s_addr >> 8;
    dhcp->options[29] = server_ip->s_addr >> 16;
    dhcp->options[30] = server_ip->s_addr >> 24;

    // fill dhcp subnet mask (1)
    dhcp->options[31] = 1;
    dhcp->options[32] = 4;
    dhcp->options[33] = this_subnet_mask[0];
    dhcp->options[34] = this_subnet_mask[1];
    dhcp->options[35] = this_subnet_mask[2];
    dhcp->options[36] = this_subnet_mask[3];
     
    // fill dhcp router
    dhcp->options[37] = 3;
    dhcp->options[38] = 4;
    dhcp->options[39] = server_ip->s_addr;
    dhcp->options[40] = server_ip->s_addr >> 8;
    dhcp->options[41] = server_ip->s_addr >> 16;
    dhcp->options[42] = server_ip->s_addr >> 24;

    // fill dhcp dns
    // se usar size ([32]) como 8 da para enviar 2 dns servers
    dhcp->options[43] = 6;
    dhcp->options[44] = 4;
    dhcp->options[45] = server_ip->s_addr;
    dhcp->options[46] = server_ip->s_addr >> 8;
    dhcp->options[47] = server_ip->s_addr >> 16;
    dhcp->options[48] = server_ip->s_addr >> 24;

    // fill dhcp broadcast
    dhcp->options[49] = 28;
    dhcp->options[50] = 4;
    dhcp->options[51] = 255;
    dhcp->options[52] = 255;
    dhcp->options[53] = 255;
    dhcp->options[54] = 255;

    // fill end
    dhcp->options[255] = 255;

    /* the IP address we're requesting */
    // if(request_specific_address==TRUE){
    //     dhcp->options[7]=DHCP_OPTION_REQUESTED_ADDRESS;
    //     dhcp->options[8]='\x04';
    //     memcpy(&dhcp->options[9],&requested_address,sizeof(requested_address));
    // }
}



void *getip(char address[4]){
	FILE *f;
	char line[100] , *p , *c;
	f = fopen("/proc/net/route" , "r");

	while(fgets(line , 100 , f))
	{
		p = strtok(line , " \t");
		c = strtok(NULL , " \t");

		if(p!=NULL && c!=NULL)
		{
			if(strcmp(c , "00000000") == 0)
			{
				printf("Default interface is : %s \n" , p);
				break;
			}
		}
	}

	//which family do we require , AF_INET or AF_INET6
	int fm = AF_INET;
	struct ifaddrs *ifaddr, *ifa;
	int family , s;
	char *host;

	if (getifaddrs(&ifaddr) == -1)
	{
		perror("getifaddrs");
		exit(EXIT_FAILURE);
	}

	//Walk through linked list, maintaining head pointer so we can free list later
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr == NULL)continue;
		
		family = ifa->ifa_addr->sa_family;
		
		if(strcmp( ifa->ifa_name , p) == 0)
		{
			if (family == fm)
			{
				s = getnameinfo( ifa->ifa_addr, (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6) , host , NI_MAXHOST , NULL , 0 , NI_NUMERICHOST);
			
				if (s != 0)
				{
					printf("getnameinfo() failed: %s\n", gai_strerror(s));
					exit(EXIT_FAILURE);
				}
			
				printf("address: %s", host);
			}
			printf("\n");
		}
	}
	freeifaddrs(ifaddr);
}

 

