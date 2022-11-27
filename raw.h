#define ETH_LEN 1518
#define ETHER_TYPE  0x0800
#define DEFAULT_IF  "eth0"
 
// ==== dhcp var
#define DHCP_UDP_OVERHEAD   (20 + /* IP header */       	\
               	8)   /* UDP header */
#define DHCP_SNAME_LEN  	64
#define DHCP_FILE_LEN   	128
#define DHCP_FIXED_NON_UDP  236
#define DHCP_FIXED_LEN  	(DHCP_FIXED_NON_UDP + DHCP_UDP_OVERHEAD)
                   	/* Everything but options. */
#define BOOTP_MIN_LEN   	300
 
#define DHCP_MTU_MAX    	1500
#define DHCP_MTU_MIN        	576
 
#define DHCP_MAX_OPTION_LEN (DHCP_MTU_MAX - DHCP_FIXED_LEN)
#define DHCP_MIN_OPTION_LEN 	(DHCP_MTU_MIN - DHCP_FIXED_LEN)
 
 
struct eth_hdr_s {
   uint8_t dst_addr[6];
   uint8_t src_addr[6];
   uint16_t eth_type;
};
 
struct ip_hdr_s {
   uint8_t ver;        	/* version, header length */
   uint8_t tos;        	/* type of service */
   int16_t len;        	/* total length */
   uint16_t id;        	/* identification */
   int16_t off;        	/* fragment offset field */
   uint8_t ttl;        	/* time to live */
   uint8_t proto;      	/* protocol */
   uint16_t sum;       	/* checksum */
   uint8_t src[4];     	/* source address */
   uint8_t dst[4];     	/* destination address */
};
 
struct udp_hdr_s {
   uint16_t src_port;
   uint16_t dst_port;
   uint16_t udp_len;
   uint16_t udp_chksum;
};
 
struct dhcp_hdr_s {
   uint8_t op;  	// message op code, message type
   uint8_t htype;   // hardware address type
   uint8_t hlen;	// hardware address length
   uint8_t hops;	// incremented by relay agents
 
   uint32_t xid;	// transaction ID
 
   uint16_t secs;   // seconds since address acquisition or renewal
   uint16_t flags;  // flags
 
   // uint32_t ciaddr; // client IP address
   // uint32_t yiaddr; // 'your' client IP address
   // uint32_t siaddr; // IP address of the next server to use in bootstrap
   // uint32_t giaddr; // relay agent IP address
 
   uint8_t ciaddr[4]; // client IP address
   uint8_t yiaddr[4]; // 'your' client IP address
   uint8_t siaddr[4]; // IP address of the next server to use in bootstrap
   uint8_t giaddr[4]; // relay agent IP address
 
   uint8_t chaddr[4]; // client hardware address
 
   uint8_t sname[64]; // server host name
 
   uint8_t file[128]; // boot file name
 
   uint8_t options[212]; // optional parameters field
 
///
   //u_int8_t  op;  	/* 0: Message opcode/type */
   //u_int8_t  htype;	/* 1: Hardware addr type (net/if_types.h) */
   //u_int8_t  hlen; 	/* 2: Hardware addr length */
   //u_int8_t  hops; 	/* 3: Number of relay agent hops from client */
   //u_int32_t xid;  	/* 4: Transaction ID */
   //u_int16_t secs; 	/* 8: Seconds since client started looking */
   //u_int16_t flags;	/* 10: Flag bits */
   //struct in_addr ciaddr;  /* 12: Client IP address (if already in use) */
   //struct in_addr yiaddr;  /* 16: Client IP address */
   //struct in_addr siaddr;  /* 18: IP address of next server to talk to */
   //struct in_addr giaddr;  /* 20: DHCP relay agent IP address */
   //unsigned char chaddr [16];  /* 24: Client hardware address */
   //char sname [DHCP_SNAME_LEN];	/* 40: Server name */
   //char file [DHCP_FILE_LEN];  /* 104: Boot filename */
   //unsigned char options [DHCP_MAX_OPTION_LEN];
           	/* 212: Optional parameters
         	(actual length dependent on MTU). */
};
 
struct eth_frame_s {
   struct eth_hdr_s ethernet;
   struct ip_hdr_s ip;
   struct udp_hdr_s udp;
   struct dhcp_hdr_s dhcp;
};
