#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#define u_int8_t     uint8_t
#define u_int16_t    uint16_t
#define u_int32_t    uint32_t

#define HAVE_GETOPT_H

#define usage printf

/**** Common definitions ****/

#define STATE_OK          0
#define STATE_WARNING     1
#define STATE_CRITICAL    2
#define STATE_UNKNOWN     -1

#define OK                0
#define ERROR             -1

#define FALSE             0
#define TRUE              1


/**** DHCP definitions ****/

#define MAX_DHCP_CHADDR_LENGTH           16
#define MAX_DHCP_SNAME_LENGTH            64
#define MAX_DHCP_FILE_LENGTH             128
#define MAX_DHCP_OPTIONS_LENGTH          312


#define BOOTREQUEST     1
#define BOOTREPLY       2

#define DHCPDISCOVER    1
#define DHCPOFFER       2
#define DHCPREQUEST     3
#define DHCPDECLINE     4
#define DHCPACK         5
#define DHCPNACK        6
#define DHCPRELEASE     7

#define DHCP_OPTION_MESSAGE_TYPE        53
#define DHCP_OPTION_HOST_NAME           12
#define DHCP_OPTION_BROADCAST_ADDRESS   28
#define DHCP_OPTION_REQUESTED_ADDRESS   50
#define DHCP_OPTION_LEASE_TIME          51
#define DHCP_OPTION_RENEWAL_TIME        58
#define DHCP_OPTION_REBINDING_TIME      59

#define DHCP_INFINITE_TIME              0xFFFFFFFF

#define DHCP_UNICAST_FLAG 0
#define DHCP_BROADCAST_FLAG 32768

#define DHCP_SERVER_PORT   67
#define DHCP_CLIENT_PORT   68

#define ETHERNET_HARDWARE_ADDRESS            1     /* used in htype field of dhcp packet */
#define ETHERNET_HARDWARE_ADDRESS_LENGTH     6     /* length of Ethernet hardware addresses */

#define ETH_LEN 1518
#define ETHER_TYPE  0x0800
#define DEFAULT_IF  "eth0"
 
struct eth_hdr_s {
   uint8_t dst_addr[6];
   uint8_t src_addr[6];
   uint16_t eth_type;
};
 
struct ip_hdr_s {
   uint8_t ver;         /* version, header length */
   uint8_t tos;         /* type of service */
   int16_t len;         /* total length */
   uint16_t id;         /* identification */
   int16_t off;         /* fragment offset field */
   uint8_t ttl;         /* time to live */
   uint8_t proto;       /* protocol */
   uint16_t sum;        /* checksum */
   uint8_t src[4];      /* source address */
   uint8_t dst[4];      /* destination address */
};
 
struct udp_hdr_s {
   uint16_t src_port;
   uint16_t dst_port;
   uint16_t udp_len;
   uint16_t udp_chksum;
};
 
struct dhcp_hdr_s {
   uint8_t op;    // message op code, message type
   uint8_t htype;   // hardware address type
   uint8_t hlen;  // hardware address length
   uint8_t hops;  // incremented by relay agents
 
   uint32_t xid;  // transaction ID
 
   uint16_t secs;   // seconds since address acquisition or renewal
   uint16_t flags;  // flags
 
   // uint32_t ciaddr; // client IP address
   // uint32_t yiaddr; // 'your' client IP address
   // uint32_t siaddr; // IP address of the next server to use in bootstrap
   // uint32_t giaddr; // relay agent IP address
 
   // same size as uint32
   // uint8_t ciaddr[4]; // client IP address
   // uint8_t yiaddr[4]; // 'your' client IP address
   // uint8_t siaddr[4]; // IP address of the next server to use in bootstrap
   // uint8_t giaddr[4]; // relay agent IP address

   struct in_addr ciaddr;          /* IP address of this machine (if we already have one) */
   struct in_addr yiaddr;          /* IP address of this machine (offered by the DHCP server) */
   struct in_addr siaddr;          /* IP address of DHCP server */
   struct in_addr giaddr;          /* IP address of DHCP relay */
 
   // uint8_t chaddr[6]; // client hardware address
 
   // uint8_t sname[64]; // server host name
 
   // uint8_t file[128]; // boot file name
 
   // uint8_t options[312]; // optional parameters field
   unsigned char chaddr [MAX_DHCP_CHADDR_LENGTH];      /* hardware address of this machine */
   char sname [MAX_DHCP_SNAME_LENGTH];    /* name of DHCP server */
   char file [MAX_DHCP_FILE_LENGTH];      /* boot file name (used for diskless booting?) */
   char options[MAX_DHCP_OPTIONS_LENGTH];  /* options */
};
 
struct eth_frame_s {
   struct eth_hdr_s ethernet;
   struct ip_hdr_s ip;
   struct udp_hdr_s udp;
   struct dhcp_hdr_s dhcp;
};