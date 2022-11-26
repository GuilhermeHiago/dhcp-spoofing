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
#include<errno.h>   //errno
#include<netdb.h>
#include<ifaddrs.h>
#include<unistd.h>
void *getip(char host[4]);
char this_mac[6];
char bcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char dst_mac[6] =   {0x00, 0x00, 0x00, 0x22, 0x22, 0x22};
char src_mac[6] =   {0x00, 0x00, 0x00, 0x33, 0x33, 0x33};
uint8_t broadcast_address[4] = {255, 255, 255, 255};
uint8_t client_init_address[4] = {0, 0, 0, 0};
uint8_t this_address[4] = {192, 0, 2, 1};
int main(int argc, char *argv[])
{
//    getip(this_address);
  memcpy(this_address, this_address, 4);
  struct ifreq if_idx, if_mac, ifopts;
  char ifName[IFNAMSIZ];
  struct sockaddr_ll socket_address;
  int sockfd, numbytes, size = 100;
   uint8_t raw_buffer[ETH_LEN];
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
 
  /* fill dhcp --offer */
  raw->dhcp.op = htons(2);
//    raw->dhcp.htype = 0x01; // ta alterando o hops
//    raw->dhcp.hlen = 20; // alterando 1 dos numeros de transaction ID
//    raw->dhcp.hops = 0;
//    raw->dhcp.xid = htonl(0x49ee5a54); // aleatorio mas sempre igual em 1 transaçao
//    raw->dhcp.secs = htons(0); //
//    raw->dhcp.flags = htons(0x0);
//    raw->dhcp.options[1] = 4;
//    memcpy(raw->dhcp.ciaddr, client_init_address, 4);
//    memcpy(raw->dhcp.yiaddr, client_init_address, 4);
//    memcpy(raw->dhcp.giaddr, client_init_address, 4);
//    memcpy(raw->dhcp.chaddr, dst_mac, 6);
  /* Send it.. */
  memcpy(socket_address.sll_addr, dst_mac, 6);
  if (sendto(sockfd, raw_buffer, sizeof(struct eth_hdr_s) + sizeof(struct ip_hdr_s) + sizeof(struct udp_hdr_s) + sizeof(struct dhcp_hdr_s), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
      printf("Send failed\n");
  return 0;
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
      if (ifa->ifa_addr == NULL)
      {
          continue;
      }
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
 

