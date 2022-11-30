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

#define PROTO_UDP 17
#define DST_PORT 8000

int receive_dhcp_packet(struct eth_frame_s *socket, uint8_t *raw_buffer[ETH_LEN]);

char bcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char dst_mac[6] = {0x00, 0x00, 0x00, 0x22, 0x22, 0x22};
char src_mac[6] = {0x00, 0x00, 0x00, 0x33, 0x33, 0x33};

int main(int argc, char *argv[])
{
    struct ifreq ifopts;
    char ifName[IFNAMSIZ];
    int sockfd, numbytes;
    char *p;
    uint8_t raw_buffer[ETH_LEN];
    bzero(raw_buffer, ETH_LEN);
    struct eth_frame_s *raw = (struct eth_frame_s *)&raw_buffer;

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

    /* End of configuration. Now we can receive data using raw sockets. */

    receive_dhcp_packet(socket, raw_buffer);
    // while (1){
    //     numbytes = recvfrom(sockfd, raw_buffer, ETH_LEN, 0, NULL, NULL);
    
    //     if (raw->ethernet.eth_type == ntohs(ETH_P_IP)){

    //         if (raw->ip.proto == 17){
    //             unsigned int port_dest = (unsigned int) ntohs(raw->udp.dst_port);
            
    //             if(port_dest == 67 || port_dest == 68) {
    //                 struct dhcp_hdr_s *dhcp = (struct dhcp_hdr_s *)&raw_buffer[sizeof(struct eth_hdr_s)+sizeof(struct ip_hdr_s)+sizeof(struct udp_hdr_s)];

    //                 if(dhcp->op == 1)printf("eh DHCP request\n");

    //                 printf("op type: %d = %d\n", raw->dhcp.op, dhcp->op);
    //                 printf("msg type type: %d = %d\n", raw->dhcp.options[6], dhcp->options[6]);

    //                 //dhcp->op == 1 -> dhcp request (discover/request)
    //                 //dhcp->options[6] == 1(DHCPDISCOVER) -> dchp discover
    //                 //dhcp->options[6] == 3(DHCPREQUEST) -> dchp request

    //                 printf("IP packet, %d bytes - src ip: %d.%d.%d.%d dst ip: %d.%d.%d.%d proto: %d\n",
    //                     numbytes,
    //                     raw->ip.src[0], raw->ip.src[1], raw->ip.src[2], raw->ip.src[3],
    //                     raw->ip.dst[0], raw->ip.dst[1], raw->ip.dst[2], raw->ip.dst[3],
    //                     raw->ip.proto
    //                 );

    //                 printf("sucesso\n");
    //             }else{
    //                 printf("%d",port_dest);
    //             }
    //         }
    //         continue;
    //     }
            
        //printf("got a packet, %d bytes\n", numbytes);
    }

    return 0;
}

int receive_dhcp_packet(struct eth_frame_s socket, uint8_t raw_buffer[ETH_LEN]){

    while (1){
        numbytes = recvfrom(sockfd, raw_buffer, ETH_LEN, 0, NULL, NULL);
    
        if (raw->ethernet.eth_type == ntohs(ETH_P_IP)){

            if (raw->ip.proto == 17){
                unsigned int port_dest = (unsigned int) ntohs(raw->udp.dst_port);
            
                if(port_dest == 67 || port_dest == 68) {
                    struct dhcp_hdr_s *dhcp = (struct dhcp_hdr_s *)&raw_buffer[sizeof(struct eth_hdr_s)+sizeof(struct ip_hdr_s)+sizeof(struct udp_hdr_s)];

                    if(dhcp->op == 1)printf("eh DHCP request\n");

                    printf("op type: %d = %d\n", raw->dhcp.op, dhcp->op);
                    printf("msg type type: %d = %d\n", raw->dhcp.options[6], dhcp->options[6]);

                    //dhcp->op == 1 -> dhcp request (discover/request)
                    //dhcp->options[6] == 1(DHCPDISCOVER) -> dchp discover
                    //dhcp->options[6] == 3(DHCPREQUEST) -> dchp request

                    printf("IP packet, %d bytes - src ip: %d.%d.%d.%d dst ip: %d.%d.%d.%d proto: %d\n",
                        numbytes,
                        raw->ip.src[0], raw->ip.src[1], raw->ip.src[2], raw->ip.src[3],
                        raw->ip.dst[0], raw->ip.dst[1], raw->ip.dst[2], raw->ip.dst[3],
                        raw->ip.proto
                    );

                    // return 1;
                }
            }
        }
    }
}