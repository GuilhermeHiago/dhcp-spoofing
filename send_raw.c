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

#define PROTO_UDP 17
#define DST_PORT 8000
 
void *getip();
int get_hardware_address(int sock, char *interface_name);
void send_dhcp_offer(struct dhcp_hdr_s *dhcp);
void send_dhcp_ack(struct dhcp_hdr_s *dhcp);

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
char spoofing_ip[13] = "192.0.2.70"; // ((in_addr_t)0x010200c0);

uint32_t client_xid;
unsigned char client_hardware_address[MAX_DHCP_CHADDR_LENGTH]="";
unsigned int my_client_mac[MAX_DHCP_CHADDR_LENGTH];
int mymac = 0;
 
// mac on vm: 080027424683

int main(int argc, char *argv[])
{

    struct ifaddrs *id;
    getifaddrs(&id);

    printf("Network Address of %s :- %d\n",id->ifa_name,id->ifa_addr);
    inet_ntoa(id, &this_ip)
    printf("IP: %d", this_ip);
    /////////////////////////////////////////////////////
    //// INIT SENDER SOCKET
    /////////////////////////////////////////////////////
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
    /////////////////////////////////////////////////////

    /////////////////////////////////////////////////////
    //// INIT LISTENER SOCKET
    /////////////////////////////////////////////////////
    struct ifreq ifopts2;
    int sock_listener;
    uint8_t raw_buffer2[ETH_LEN];
    bzero(raw_buffer2, ETH_LEN);
    struct eth_frame_s *raw_listener = (struct eth_frame_s *)&raw_buffer2;

    /* Open RAW socket */
    if ((sock_listener = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
        perror("socket");

    /* Set interface to promiscuous mode */
    strncpy(ifopts2.ifr_name, ifName, IFNAMSIZ-1);
    ioctl(sock_listener, SIOCGIFFLAGS, &ifopts2);
    ifopts2.ifr_flags |= IFF_PROMISC;
    ioctl(sock_listener, SIOCSIFFLAGS, &ifopts2);
    /////////////////////////////////////////////////////


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

    get_hardware_address(sockfd, ifName);
    printf("mac: %s", client_hardware_address);

	/* End of configuration. Now we can send data using raw sockets. */
	/* To send data (in this case we will cook an ARP packet and broadcast it =])... */
	/* fill the Ethernet frame header */
	memcpy(raw->ethernet.dst_addr, dst_mac, 6);
	memcpy(raw->ethernet.src_addr, src_mac, 6); // ALTERAR SRC MAC
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

    /////////////////////////////////////////////////////
    //// INIT LISTENER SOCKET
    /////////////////////////////////////////////////////
    receive_dhcp_packet(DHCPDISCOVER, sock_listener, raw_buffer2, raw_listener);
    /////////////////////////////////////////////////////
	
    /////////////////////////////////////////////////////
    //// INIT LISTENER SOCKET
    /////////////////////////////////////////////////////

    /* In truth this fill dhcp */
    send_dhcp_offer(dhcp);
    
    /* Send it.. */
    memcpy(socket_address.sll_addr, dst_mac, 6);
    if (sendto(sockfd, raw_buffer, sizeof(struct eth_hdr_s) + sizeof(struct ip_hdr_s) + sizeof(struct udp_hdr_s) + sizeof(struct dhcp_hdr_s), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
        printf("Send failed\n");
    /////////////////////////////////////////////////////


    /////////////////////////////////////////////////////
    //// INIT LISTENER SOCKET
    /////////////////////////////////////////////////////
    receive_dhcp_packet(DHCPREQUEST, sock_listener, raw_buffer2, raw_listener);
    /////////////////////////////////////////////////////


    /////////////////////////////////////////////////////
    //// INIT LISTENER SOCKET
    /////////////////////////////////////////////////////

    /* clean */
    bzero(dhcp, sizeof(struct dhcp_hdr_s));
    /* In truth this fill dhcp */
    send_dhcp_ack(dhcp);
	
    /* Send it.. */
	memcpy(socket_address.sll_addr, dst_mac, 6);
	
    if (sendto(sockfd, raw_buffer, sizeof(struct eth_hdr_s) + sizeof(struct ip_hdr_s) + sizeof(struct udp_hdr_s) + sizeof(struct dhcp_hdr_s), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
        printf("Send failed\n");
    /////////////////////////////////////////////////////

	return 0;
}
 

/* determines hardware address on client machine */
int get_hardware_address(int sock, char *interface_name){

    int i;
    struct ifreq ifr;

    strncpy((char *)&ifr.ifr_name,interface_name,sizeof(ifr.ifr_name));
    
    // Added code to try to set local MAC address just to be through
    // If this fails the test will still work since
    // we do encode the MAC as part of the DHCP frame - tests show it works
    if(mymac)
    { 
        int i;
        
        for(i=0;i<MAX_DHCP_CHADDR_LENGTH;++i)
            client_hardware_address[i] = my_client_mac[i];
        
        memcpy(&ifr.ifr_hwaddr.sa_data,&client_hardware_address[0],6);
        
        if(ioctl(sock,SIOCSIFHWADDR,&ifr)<0){
            printf("Error: Could not set hardware address of interface '%s'\n",interface_name);
        }

    }
    else
    {
        /* try and grab hardware address of requested interface */
        if(ioctl(sock,SIOCGIFHWADDR,&ifr)<0){
            printf("Error: Could not get hardware address of interface '%s'\n",interface_name);
            exit(STATE_UNKNOWN);
            }
        memcpy(&client_hardware_address[0],&ifr.ifr_hwaddr.sa_data,6);
    }

    // if (1) { 
    //     printf("Hardware address: ");
    //     for (i=0; i<6; ++i)
    //         printf("%2.2x", client_hardware_address[i]);
    //     printf( "\n");
    // }

    return OK;
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
    // packet_xid=client_xid;
    dhcp->xid=client_xid;

    /**** WHAT THE HECK IS UP WITH THIS?!?  IF I DON'T MAKE THIS CALL, ONLY ONE SERVER RESPONSE IS PROCESSED!!!! ****/
    /* downright bizzarre... */
    // ntohl(dhcp->xid);

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
    packet_xid=client_xid;
    // dhcp->xid=htonl(packet_xid);

    /**** WHAT THE HECK IS UP WITH THIS?!?  IF I DON'T MAKE THIS CALL, ONLY ONE SERVER RESPONSE IS PROCESSED!!!! ****/
    /* downright bizzarre... */
    // ntohl(dhcp->xid);

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
    memcpy(dhcp->chaddr, client_hardware_address, ETHERNET_HARDWARE_ADDRESS_LENGTH);

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



void receive_dhcp_packet(int dhcp_message_type, struct eth_frame_s *sockfd, uint8_t raw_buffer[ETH_LEN], struct eth_frame_s *raw){

    while (1){
        int numbytes = recvfrom(sockfd, raw_buffer, ETH_LEN, 0, NULL, NULL);
    
        if (raw->ethernet.eth_type == ntohs(ETH_P_IP)){

            if (raw->ip.proto == 17){
                unsigned int port_dest = (unsigned int) ntohs(raw->udp.dst_port);
            
                // filter packets by port
                if(port_dest == 67 || port_dest == 68) {
                    
                    struct dhcp_hdr_s *dhcp = (struct dhcp_hdr_s *)&raw_buffer[sizeof(struct eth_hdr_s)+sizeof(struct ip_hdr_s)+sizeof(struct udp_hdr_s)];
                    
                    // jump packets unlike the dhcp_message_type
                    if(dhcp->options[6] != dhcp_message_type){continue;}

                    //dhcp->op == 1 -> dhcp request (discover/request)
                    //dhcp->options[6] == 1(DHCPDISCOVER) -> dchp discover
                    //dhcp->options[6] == 3(DHCPREQUEST) -> dchp request

                    // if (1) { 
                    //     printf("Hardware address: ");
                    //     for (int i=0; i<6; ++i)
                    //         printf("%2.2x", dhcp->chaddr[i]);
                    //     printf( "\n");
                    // }

                    // if its a DISCOVER saves initial values
                    if(dhcp_message_type == DHCPDISCOVER){
                        memcpy(client_hardware_address, dhcp->chaddr, 6);
                        memcpy(dst_mac, dhcp->chaddr, 6);
                        client_xid = dhcp->xid;
                        printf("get xid: %d", client_xid);
                        // memcpy(dst_mac, raw->ethernet.src_addr, 6);
                    }

                    // printf("IP packet, %d bytes - src ip: %d.%d.%d.%d dst ip: %d.%d.%d.%d proto: %d\n",
                    //     numbytes,
                    //     raw->ip.src[0], raw->ip.src[1], raw->ip.src[2], raw->ip.src[3],
                    //     raw->ip.dst[0], raw->ip.dst[1], raw->ip.dst[2], raw->ip.dst[3],
                    //     raw->ip.proto
                    // );

                    break;
                }
            }
        }
    }
}


void *getip(){
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
