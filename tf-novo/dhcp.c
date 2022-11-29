//https://cs.uwaterloo.ca/twiki/pub/CF/DhcpDebug/dhcp.c

#include "raw.h"

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

// Example: dhcp -i eth0

#include <linux/if_ether.h>
#include <features.h>

unsigned char client_hardware_address[MAX_DHCP_CHADDR_LENGTH]="";
unsigned int my_client_mac[MAX_DHCP_CHADDR_LENGTH];
int mymac = 0;

char network_interface_name[9]="wlp0s20f3";//"eth0";

u_int32_t packet_xid=0;

u_int32_t dhcp_lease_time=0;
u_int32_t dhcp_renewal_time=0;
u_int32_t dhcp_rebinding_time=0;

int dhcpoffer_timeout=2;

dhcp_offer *dhcp_offer_list=NULL;
requested_server *requested_server_list=NULL;

int valid_responses=0;     /* number of valid DHCPOFFERs we received */
int requested_servers=0;   
int requested_responses=0;

int request_specific_address=FALSE;
int received_requested_address=FALSE;
int verbose=0;
struct in_addr requested_address;


int process_arguments(int, char **);
int call_getopt(int, char **);
int validate_arguments(void);
void print_usage(void);

int get_hardware_address(int,char *);

int send_dhcp_discover(int);
int get_dhcp_offer(int);

int get_results(void);

int add_dhcp_offer(struct in_addr,dhcp_packet *);
int free_dhcp_offer_list(void);
int free_requested_server_list(void);

int create_dhcp_socket(void);
int close_dhcp_socket(int);
int send_dhcp_packet(void *,int,int,struct sockaddr_in *);
int receive_dhcp_packet(void *,int,int,int,struct sockaddr_in *);


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


int main(int argc, char **argv){
    int dhcp_socket;
    int result;

    setlocale (LC_ALL, "");
    
    if(process_arguments(argc,argv)!=OK){
        printf("Could not parse arguments");
    }

    /* create socket for DHCP communications */
    dhcp_socket=create_dhcp_socket();

    /* get hardware address of client machine */
    get_hardware_address(dhcp_socket,network_interface_name);

    verbose = TRUE;

    /* send DHCPDISCOVER packet */
    // send_dhcp_discover(dhcp_socket);
    // send_dhcp_offer(dhcp_socket);
    send_dhcp_ack(dhcp_socket);

    /* wait for a DHCPOFFER packet */
    get_dhcp_offer(dhcp_socket);

    /* close socket we created */
    close_dhcp_socket(dhcp_socket);

    /* determine state/plugin output to return */
    result=get_results();

    /* free allocated memory */
    free_dhcp_offer_list();
    free_requested_server_list();

    return result;
}


/* determines hardware address on client machine */
int get_hardware_address(int sock,char *interface_name){

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

    if (verbose) { 
        printf("Hardware address: ");
        for (i=0; i<6; ++i)
            printf("%2.2x", client_hardware_address[i]);
        printf( "\n");
    }

    return OK;
}


/* sends a DHCPDISCOVER broadcast message in an attempt to find DHCP servers */
int send_dhcp_discover(int sock){
    dhcp_packet discover_packet;
    struct sockaddr_in sockaddr_broadcast;


    /* clear the packet data structure */
    bzero(&discover_packet,sizeof(discover_packet));


    /* boot request flag (backward compatible with BOOTP servers) */
    discover_packet.op=BOOTREQUEST;

    /* hardware address type */
    discover_packet.htype=ETHERNET_HARDWARE_ADDRESS;

    /* length of our hardware address */
    discover_packet.hlen=ETHERNET_HARDWARE_ADDRESS_LENGTH;

    discover_packet.hops=0;

    /* transaction id is supposed to be random */
    srand(time(NULL));
    packet_xid=random();
    discover_packet.xid=htonl(packet_xid);

    /**** WHAT THE HECK IS UP WITH THIS?!?  IF I DON'T MAKE THIS CALL, ONLY ONE SERVER RESPONSE IS PROCESSED!!!! ****/
    /* downright bizzarre... */
    ntohl(discover_packet.xid);

    /*discover_packet.secs=htons(65535);*/
    discover_packet.secs=0xFF;

    /* tell server it should broadcast its response */ 
    discover_packet.flags=htons(DHCP_BROADCAST_FLAG);

    /* our hardware address */
    memcpy(discover_packet.chaddr,client_hardware_address,ETHERNET_HARDWARE_ADDRESS_LENGTH);

    /* first four bytes of options field is magic cookie (as per RFC 2132) */
    discover_packet.options[0]='\x63';
    discover_packet.options[1]='\x82';
    discover_packet.options[2]='\x53';
    discover_packet.options[3]='\x63';

    /* DHCP message type is embedded in options field */
    discover_packet.options[4]=DHCP_OPTION_MESSAGE_TYPE;    /* DHCP message type option identifier */
    discover_packet.options[5]='\x01';               /* DHCP message option length in bytes */
    discover_packet.options[6]=DHCPDISCOVER;

    // TAVA FALTANDO O END
    discover_packet.options[255] = 255;

    /* the IP address we're requesting */
    if(request_specific_address==TRUE){
        discover_packet.options[7]=DHCP_OPTION_REQUESTED_ADDRESS;
        discover_packet.options[8]='\x04';
        memcpy(&discover_packet.options[9],&requested_address,sizeof(requested_address));
            }
    
    /* send the DHCPDISCOVER packet to broadcast address */
        sockaddr_broadcast.sin_family=AF_INET;
        sockaddr_broadcast.sin_port=htons(DHCP_CLIENT_PORT);
        sockaddr_broadcast.sin_addr.s_addr=INADDR_BROADCAST;
        // inet_pton(AF_INET, ip_manda, sockaddr_broadcast.sin_addr.s_addr);

        // envia para o dhcp server pucrs 192.0.2.1
        // sockaddr_broadcast.sin_addr.s_addr = ((in_addr_t)0x010200c0);


    bzero(&sockaddr_broadcast.sin_zero,sizeof(sockaddr_broadcast.sin_zero));


    if (verbose) {
        printf("DHCPDISCOVER to %s port %d\n",inet_ntoa(sockaddr_broadcast.sin_addr),ntohs(sockaddr_broadcast.sin_port));
        printf("DHCPDISCOVER XID: %lu (0x%X)\n",(unsigned long) ntohl(discover_packet.xid),ntohl(discover_packet.xid));
        printf("DHCDISCOVER ciaddr:  %s\n",inet_ntoa(discover_packet.ciaddr));
        printf("DHCDISCOVER yiaddr:  %s\n",inet_ntoa(discover_packet.yiaddr));
        printf("DHCDISCOVER siaddr:  %s\n",inet_ntoa(discover_packet.siaddr));
        printf("DHCDISCOVER giaddr:  %s\n",inet_ntoa(discover_packet.giaddr));
    }

    /* send the DHCPDISCOVER packet out */
    send_dhcp_packet(&discover_packet,sizeof(discover_packet),sock,&sockaddr_broadcast);

    if (verbose) 
        printf("\n\n");

    return OK;
}




/* waits for a DHCPOFFER message from one or more DHCP servers */
int get_dhcp_offer(int sock){
    dhcp_packet offer_packet;
    struct sockaddr_in source;
    int result=OK;
    int timeout=1;
    int responses=0;
    int x;
    time_t start_time;
    time_t current_time;

    time(&start_time);

    /* receive as many responses as we can */
    for(responses=0,valid_responses=0;;){

        time(&current_time);
        if((current_time-start_time)>=dhcpoffer_timeout)
            break;

        if (verbose) 
            printf("\n\n");

        bzero(&source,sizeof(source));
        bzero(&offer_packet,sizeof(offer_packet));

        result=OK;
        result=receive_dhcp_packet(&offer_packet,sizeof(offer_packet),sock,dhcpoffer_timeout,&source);
        
        if(result!=OK){
            if (verbose)
                printf("Result=ERROR\n");

            continue;
                }
        else{
            if (verbose) 
                printf("Result=OK\n");

            responses++;
                }

        if (verbose) {
            printf("DHCPOFFER from IP address %s\n",inet_ntoa(source.sin_addr));
            printf("DHCPOFFER XID: %lu (0x%X)\n",(unsigned long) ntohl(offer_packet.xid),ntohl(offer_packet.xid));
        }

        /* check packet xid to see if its the same as the one we used in the discover packet */
        if(ntohl(offer_packet.xid)!=packet_xid){
            if (verbose)
                printf("DHCPOFFER XID (%lu) did not match DHCPDISCOVER XID (%lu) - ignoring packet\n",(unsigned long) ntohl(offer_packet.xid),(unsigned long) packet_xid);

            continue;
                }

        /* check hardware address */
        result=OK;
        if (verbose)
            printf("DHCPOFFER chaddr: ");

        for(x=0;x<ETHERNET_HARDWARE_ADDRESS_LENGTH;x++){
            if (verbose)
                printf("%02X",(unsigned char)offer_packet.chaddr[x]);

            if(offer_packet.chaddr[x]!=client_hardware_address[x])
                result=ERROR;
        }
        if (verbose)
            printf("\n");

        if(result==ERROR){
            if (verbose) 
                printf("DHCPOFFER hardware address did not match our own - ignoring packet\n");

            continue;
                }

        if (verbose) {
            printf("DHCPOFFER ciaddr: %s\n",inet_ntoa(offer_packet.ciaddr));
            printf("DHCPOFFER yiaddr: %s\n",inet_ntoa(offer_packet.yiaddr));
            printf("DHCPOFFER siaddr: %s\n",inet_ntoa(offer_packet.siaddr));
            printf("DHCPOFFER giaddr: %s\n",inet_ntoa(offer_packet.giaddr));
        }

        add_dhcp_offer(source.sin_addr,&offer_packet);

        valid_responses++;
            }

    if (verbose) {
        printf("Total responses seen on the wire: %d\n",responses);
        printf("Valid responses for this machine: %d\n",valid_responses);
    }

    return OK;
        }



/* sends a DHCP packet */
int send_dhcp_packet(void *buffer, int buffer_size, int sock, struct sockaddr_in *dest){
    struct sockaddr_in myname;
    int result;

    result=sendto(sock,(char *)buffer,buffer_size,0,(struct sockaddr *)dest,sizeof(*dest));

    if (verbose) 
        printf("send_dhcp_packet result: %d\n",result);

    if(result<0)
        return ERROR;

    return OK;
}



/* receives a DHCP packet */
int receive_dhcp_packet(void *buffer, int buffer_size, int sock, int timeout, struct sockaddr_in *address){
        struct timeval tv;
        fd_set readfds;
    int recv_result;
    socklen_t address_size;
    struct sockaddr_in source_address;


        /* wait for data to arrive (up time timeout) */
        tv.tv_sec=timeout;
        tv.tv_usec=0;
        FD_ZERO(&readfds);
        FD_SET(sock,&readfds);
        select(sock+1,&readfds,NULL,NULL,&tv);

        /* make sure some data has arrived */
        if(!FD_ISSET(sock,&readfds)){
        if (verbose)
                    printf("No (more) data received\n");
                return ERROR;
                }

        else{

        /* why do we need to peek first?  i don't know, its a hack.  without it, the source address of the first packet received was
           not being interpreted correctly.  sigh... */
        bzero(&source_address,sizeof(source_address));
        address_size=sizeof(source_address);
                recv_result=recvfrom(sock,(char *)buffer,buffer_size,MSG_PEEK,(struct sockaddr *)&source_address,&address_size);
        if (verbose)
            printf("recv_result_1: %d\n",recv_result);
                recv_result=recvfrom(sock,(char *)buffer,buffer_size,0,(struct sockaddr *)&source_address,&address_size);
        if (verbose)
            printf("recv_result_2: %d\n",recv_result);

                if(recv_result==-1){
            if (verbose) {
                printf("recvfrom() failed, ");
                printf("errno: (%d) -> %s\n",errno,strerror(errno));
            }
                        return ERROR;
                        }
        else{
            if (verbose) {
                printf("receive_dhcp_packet() result: %d\n",recv_result);
                printf("receive_dhcp_packet() source: %s\n",inet_ntoa(source_address.sin_addr));
            }

            memcpy(address,&source_address,sizeof(source_address));
            return OK;
                }
                }

    return OK;
        }


/* creates a socket for DHCP communication */
int create_dhcp_socket(void){
    struct sockaddr_in myname;
    struct ifreq interface;
    int sock;
    int flag=1;

        /* Set up the address we're going to bind to. */
    bzero(&myname,sizeof(myname));
        myname.sin_family=AF_INET;
        myname.sin_port=htons(DHCP_SERVER_PORT);
        myname.sin_addr.s_addr=INADDR_ANY;                 /* listen on any address */
        bzero(&myname.sin_zero,sizeof(myname.sin_zero));

        /* create a socket for DHCP communications */
    sock=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
        if(sock<0){
        printf("Error: Could not create socket!\n");
        exit(STATE_UNKNOWN);
            }

    if (verbose)
        printf("DHCP socket: %d\n",sock);

        /* set the reuse address flag so we don't get errors when restarting */
        flag=1;
        if(setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(char *)&flag,sizeof(flag))<0){
        printf("Error: Could not set reuse address option on DHCP socket!\n");
        exit(STATE_UNKNOWN);
            }

        /* set the broadcast option - we need this to listen to DHCP broadcast messages */
        if(setsockopt(sock,SOL_SOCKET,SO_BROADCAST,(char *)&flag,sizeof flag)<0){
        printf("Error: Could not set broadcast option on DHCP socket!\n");
        exit(STATE_UNKNOWN);
            }

    /* bind socket to interface */
#if defined(__linux__)
    strncpy(interface.ifr_ifrn.ifrn_name,network_interface_name,IFNAMSIZ);
    if(setsockopt(sock,SOL_SOCKET,SO_BINDTODEVICE,(char *)&interface,sizeof(interface))<0){
        printf("Error: Could not bind socket to interface %s.  Check your privileges...\n",network_interface_name);
        exit(STATE_UNKNOWN);
            }

#else
    strncpy(interface.ifr_name,network_interface_name,IFNAMSIZ);
#endif

        /* bind the socket */
        if(bind(sock,(struct sockaddr *)&myname,sizeof(myname))<0){
        printf("Error: Could not bind to DHCP socket (port %d)!  Check your privileges...\n",DHCP_SERVER_PORT);
        exit(STATE_UNKNOWN);
            }

        return sock;
        }


/* closes DHCP socket */
int close_dhcp_socket(int sock){

    close(sock);

    return OK;
        }


/* adds a requested server address to list in memory */
int add_requested_server(struct in_addr server_address){
    requested_server *new_server;

    new_server=(requested_server *)malloc(sizeof(requested_server));
    if(new_server==NULL)
        return ERROR;

    new_server->server_address=server_address;

    new_server->next=requested_server_list;
    requested_server_list=new_server;

    requested_servers++;

    if (verbose)
        printf("Requested server address: %s\n",inet_ntoa(new_server->server_address));

    return OK;
        }




/* adds a DHCP OFFER to list in memory */
int add_dhcp_offer(struct in_addr source,dhcp_packet *offer_packet){
    dhcp_offer *new_offer;
    int x;
    int y;
    unsigned option_type;
    unsigned option_length;

    if(offer_packet==NULL)
        return ERROR;

    /* process all DHCP options present in the packet */
    for(x=4;x<MAX_DHCP_OPTIONS_LENGTH;){

        /* end of options (0 is really just a pad, but bail out anyway) */
        if((int)offer_packet->options[x]==-1 || (int)offer_packet->options[x]==0)
            break;

        /* get option type */
        option_type=offer_packet->options[x++];

        /* get option length */
        option_length=offer_packet->options[x++];

        if (verbose) 
            printf("Option: %d (0x%02X)\n",option_type,option_length);

        /* get option data */
        if(option_type==DHCP_OPTION_LEASE_TIME) {
            memcpy(&dhcp_lease_time, &offer_packet->options[x],
                sizeof(dhcp_lease_time));
            dhcp_lease_time = ntohl(dhcp_lease_time);
        }
        if(option_type==DHCP_OPTION_RENEWAL_TIME) {
            memcpy(&dhcp_renewal_time, &offer_packet->options[x],
                sizeof(dhcp_renewal_time));
            dhcp_renewal_time = ntohl(dhcp_renewal_time);
        }
        if(option_type==DHCP_OPTION_REBINDING_TIME) {
            memcpy(&dhcp_rebinding_time, &offer_packet->options[x],
                sizeof(dhcp_rebinding_time));
            dhcp_rebinding_time = ntohl(dhcp_rebinding_time);
        }

        /* skip option data we're ignoring */
        else
            for(y=0;y<option_length;y++,x++);
            }

    if (verbose) {
        if(dhcp_lease_time==DHCP_INFINITE_TIME)
            printf("Lease Time: Infinite\n");
        else
            printf("Lease Time: %lu seconds\n",(unsigned long)dhcp_lease_time);
        if(dhcp_renewal_time==DHCP_INFINITE_TIME)
            printf("Renewal Time: Infinite\n");
        else
            printf("Renewal Time: %lu seconds\n",(unsigned long)dhcp_renewal_time);
        if(dhcp_rebinding_time==DHCP_INFINITE_TIME)
            printf("Rebinding Time: Infinite\n");
        printf("Rebinding Time: %lu seconds\n",(unsigned long)dhcp_rebinding_time);
    }

    new_offer=(dhcp_offer *)malloc(sizeof(dhcp_offer));

    if(new_offer==NULL)
        return ERROR;

    new_offer->server_address=source;
    new_offer->offered_address=offer_packet->yiaddr;
    new_offer->lease_time=dhcp_lease_time;
    new_offer->renewal_time=dhcp_renewal_time;
    new_offer->rebinding_time=dhcp_rebinding_time;


    if (verbose) {
        printf("Added offer from server @ %s",inet_ntoa(new_offer->server_address));
        printf(" of IP address %s\n",inet_ntoa(new_offer->offered_address));
    }

    /* add new offer to head of list */
    new_offer->next=dhcp_offer_list;
    dhcp_offer_list=new_offer;

    return OK;
        }


/* frees memory allocated to DHCP OFFER list */
int free_dhcp_offer_list(void){
    dhcp_offer *this_offer;
    dhcp_offer *next_offer;

    for(this_offer=dhcp_offer_list;this_offer!=NULL;this_offer=next_offer){
        next_offer=this_offer->next;
        free(this_offer);
            }

    return OK;
        }


/* frees memory allocated to requested server list */
int free_requested_server_list(void){
    requested_server *this_server;
    requested_server *next_server;

    for(this_server=requested_server_list;this_server!=NULL;this_server=next_server){
        next_server=this_server->next;
        free(this_server);
            }
    
    return OK;
        }


/* gets state and plugin output to return */
int get_results(void){
    dhcp_offer *temp_offer;
    requested_server *temp_server;
    int result;
    u_int32_t max_lease_time=0;

    received_requested_address=FALSE;

    /* checks responses from requested servers */
    requested_responses=0;
    if(requested_servers>0){

        for(temp_server=requested_server_list;temp_server!=NULL;temp_server=temp_server->next){

            for(temp_offer=dhcp_offer_list;temp_offer!=NULL;temp_offer=temp_offer->next){

                /* get max lease time we were offered */
                if(temp_offer->lease_time>max_lease_time || temp_offer->lease_time==DHCP_INFINITE_TIME)
                    max_lease_time=temp_offer->lease_time;
                
                /* see if we got the address we requested */
                if(!memcmp(&requested_address,&temp_offer->offered_address,sizeof(requested_address)))
                    received_requested_address=TRUE;

                /* see if the servers we wanted a response from talked to us or not */
                if(!memcmp(&temp_offer->server_address,&temp_server->server_address,sizeof(temp_server->server_address))){
    if (verbose) {
                    printf("DHCP Server Match: Offerer=%s",inet_ntoa(temp_offer->server_address));
                    printf(" Requested=%s\n",inet_ntoa(temp_server->server_address));
    }                       
                    requested_responses++;
                        }
                        }
                }

            }

    /* else check and see if we got our requested address from any server */
    else{

        for(temp_offer=dhcp_offer_list;temp_offer!=NULL;temp_offer=temp_offer->next){

            /* get max lease time we were offered */
            if(temp_offer->lease_time>max_lease_time || temp_offer->lease_time==DHCP_INFINITE_TIME)
                max_lease_time=temp_offer->lease_time;
                
            /* see if we got the address we requested */
            if(!memcmp(&requested_address,&temp_offer->offered_address,sizeof(requested_address)))
                received_requested_address=TRUE;
                    }
            }

    result=STATE_OK;
    if(valid_responses==0)
        result=STATE_CRITICAL;
    else if(requested_servers>0 && requested_responses==0)
        result=STATE_CRITICAL;
    else if(requested_responses<requested_servers)
        result=STATE_WARNING;
    else if(request_specific_address==TRUE && received_requested_address==FALSE)
        result=STATE_WARNING;


    printf("DHCP %s: ",(result==STATE_OK)?"ok":"problem");

    /* we didn't receive any DHCPOFFERs */
    if(dhcp_offer_list==NULL){
        printf("No DHCPOFFERs were received.\n");
        return result;
            }

    printf("Received %d DHCPOFFER(s)",valid_responses);

    if(requested_servers>0)
        printf(", %s%d of %d requested servers responded",((requested_responses<requested_servers) && requested_responses>0)?"only ":"",requested_responses,requested_servers);

    if(request_specific_address==TRUE)
        printf(", requested address (%s) was %soffered",inet_ntoa(requested_address),(received_requested_address==TRUE)?"":"not ");

    printf(", max lease time = ");
    if(max_lease_time==DHCP_INFINITE_TIME)
        printf("Infinity");
    else
        printf("%lu sec",(unsigned long)max_lease_time);

    printf(".\n");

    return result;
        }


/* process command-line arguments */
int process_arguments(int argc, char **argv){
    int c;

    if(argc<1)
        return ERROR;

    c=0;
    while((c+=(call_getopt(argc-c,&argv[c])))<argc){

        /*
        if(is_option(argv[c]))
            continue;
        */
    }

    return validate_arguments();
}



int call_getopt(int argc, char **argv){
    int c=0;
    int i=0;
    struct in_addr ipaddress;

#ifdef HAVE_GETOPT_H
    int option_index = 0;
    static struct option long_options[] =
    { 
        {"serverip",       required_argument,0,'s'},
        {"requestedip",    required_argument,0,'r'},
        {"timeout",        required_argument,0,'t'},
        {"interface",      required_argument,0,'i'},
        {"mac",             required_argument,0,'m'},
        {"verbose",        no_argument,      0,'v'},
        {"version",        no_argument,      0,'V'},
        {"help",           no_argument,      0,'h'},
        {0,0,0,0}
    };
#endif

    while(1){
#ifdef HAVE_GETOPT_H
        c=getopt_long(argc,argv,"+hVvt:s:r:t:i:m:",long_options,&option_index);
#else
        c=getopt(argc,argv,"+?hVvt:s:r:t:i:m:");
#endif

        i++;

        if(c==-1||c==EOF||c==1)
            break;

        switch(c){
        case 'w':
        case 'r':
        case 't':
        case 'i':
            i++;
            break;
        default:
            break;
                }

        switch(c){

        case 'm': /* Our MAC address */
            {
            int ret;
            ret = sscanf(optarg,"%x:%x:%x:%x:%x:%x", 
                my_client_mac+0,
                my_client_mac+1,
                my_client_mac+2,
                my_client_mac+3,
                my_client_mac+4,
                my_client_mac+5);
            if(ret != 6) {
                usage("Invalid MAC address\n");
                break;
            }
            for(i=0;i<6;++i) 
                client_hardware_address[i] = my_client_mac[i];
            }
            mymac = 1;
            break;
        case 's': /* DHCP server address */
            if(inet_aton(optarg,&ipaddress))
                add_requested_server(ipaddress);
            /*
            else
                usage("Invalid server IP address\n");
            */
            break;

        case 'r': /* address we are requested from DHCP servers */
            if(inet_aton(optarg,&ipaddress)){
                requested_address=ipaddress;
                request_specific_address=TRUE;
                    }
            /*
            else
                usage("Invalid requested IP address\n");
            */
            break;

        case 't': /* timeout */

            /*
            if(is_intnonneg(optarg))
            */
            if(atoi(optarg)>0)
                dhcpoffer_timeout=atoi(optarg);
            /*
            else
                usage("Time interval must be a nonnegative integer\n");
            */
            break;

        case 'i': /* interface name */

            strncpy(network_interface_name,optarg,sizeof(network_interface_name)-1);
            network_interface_name[sizeof(network_interface_name)-1]='\x0';

            break;

        case 'v': /* verbose */
            verbose=1;
            break;

        case '?': /* help */
            printf("Unknown argument:%s\n", optarg);
            break;

        default:
            break;
                }
            }

    return i;
}


int validate_arguments(void){

    return OK;
}

/* sends a DHCPDISCOVER broadcast message in an attempt to find DHCP servers */
int send_dhcp_offer(int sock){
    dhcp_packet offer_packet;
    struct sockaddr_in sockaddr_client;


    /* clear the packet data structure */
    bzero(&offer_packet,sizeof(offer_packet));


    /* boot request flag (backward compatible with BOOTP servers) */
    offer_packet.op=BOOTREPLY;

    /* hardware address type */
    offer_packet.htype=ETHERNET_HARDWARE_ADDRESS;

    /* length of our hardware address */
    offer_packet.hlen=ETHERNET_HARDWARE_ADDRESS_LENGTH;

    offer_packet.hops=0;

    /* shold get the xid from CLIENT DISCOVER */
    packet_xid=123;
    offer_packet.xid=htonl(packet_xid);

    /**** WHAT THE HECK IS UP WITH THIS?!?  IF I DON'T MAKE THIS CALL, ONLY ONE SERVER RESPONSE IS PROCESSED!!!! ****/
    /* downright bizzarre... */
    ntohl(offer_packet.xid);

    /*offer_packet.secs=htons(65535);*/
    offer_packet.secs=0xFF;

    /* tell server it should broadcast its response */ 
    offer_packet.flags=htons(DHCP_UNICAST_FLAG);

    /* Set client address*/
    inet_aton("0.0.0.0", &offer_packet.ciaddr);

    /* Set sender (server) address*/
    inet_aton(this_ip, &offer_packet.yiaddr);

    struct sockaddr_in sa;
    char buffer[INET_ADDRSTRLEN];
    inet_ntop( AF_INET, &offer_packet.yiaddr, buffer, sizeof( buffer ));

    /* Set next server address*/
    inet_aton("0.0.0.0", &offer_packet.siaddr);

    /* Set relay agent address*/
    inet_aton("0.0.0.0", &offer_packet.giaddr);

    /* our hardware address */
    memcpy(offer_packet.chaddr, client_hardware_address, ETHERNET_HARDWARE_ADDRESS_LENGTH);

    /* first four bytes of options field is magic cookie (as per RFC 2132) */
    offer_packet.options[0]='\x63';
    offer_packet.options[1]='\x82';
    offer_packet.options[2]='\x53';
    offer_packet.options[3]='\x63';

    /* DHCP message type is embedded in options field */
    offer_packet.options[4]=DHCP_OPTION_MESSAGE_TYPE;    /* DHCP message type option identifier */
    offer_packet.options[5]='\x01';               /* DHCP message option length in bytes */
    offer_packet.options[6]=DHCPOFFER;

    struct in_addr *server_ip = malloc(sizeof (struct in_addr));
    inet_aton(this_ip, server_ip);

    // fill dhcp subnet mask (1)
    offer_packet.options[7]  = 1;
    offer_packet.options[8]  = 4;
    offer_packet.options[9]  = this_subnet_mask[0];
    offer_packet.options[10] = this_subnet_mask[1];
    offer_packet.options[11] = this_subnet_mask[2];
    offer_packet.options[12] = this_subnet_mask[3];

    // fill dhcp renewal time (58)
    offer_packet.options[13] = 58;
    offer_packet.options[14] = 4;
    offer_packet.options[15] = 0;
    offer_packet.options[16] = 1;
    offer_packet.options[17] = 56;
    offer_packet.options[18] = 128;

    // fill dhcp rebinding time (59)
    offer_packet.options[19] = 59;
    offer_packet.options[20] = 4;
    offer_packet.options[21] = 0;
    offer_packet.options[22] = 1;
    offer_packet.options[23] = 56;
    offer_packet.options[24] = 128;
    
    // fill dhcp lease time (51)
    offer_packet.options[25] = 51;
    offer_packet.options[26] = 4;
    offer_packet.options[27] = 0;
    offer_packet.options[28] = 1;
    offer_packet.options[29] = 56;
    offer_packet.options[30] = 128;

    // fill dhcp server identifier    
    offer_packet.options[31] = 54;//0xff; 
    offer_packet.options[32] = 4; 
    offer_packet.options[33] = server_ip->s_addr; 
    offer_packet.options[34] = server_ip->s_addr >> 8;
    offer_packet.options[35] = server_ip->s_addr >> 16;
    offer_packet.options[36] = server_ip->s_addr >> 24;
     
    // fill dhcp router
    offer_packet.options[37] = 3;
    offer_packet.options[38] = 4;
    offer_packet.options[39] = server_ip->s_addr;
    offer_packet.options[40] = server_ip->s_addr >> 8;
    offer_packet.options[41] = server_ip->s_addr >> 16;
    offer_packet.options[42] = server_ip->s_addr >> 24;

    // fill dhcp dns
    // se usar size ([32]) como 8 da para enviar 2 dns servers
    offer_packet.options[43] = 6;
    offer_packet.options[44] = 4;
    offer_packet.options[45] = server_ip->s_addr;
    offer_packet.options[46] = server_ip->s_addr >> 8;
    offer_packet.options[47] = server_ip->s_addr >> 16;
    offer_packet.options[48] = server_ip->s_addr >> 24;

    // fill dhcp broadcast
    offer_packet.options[49] = 28;
    offer_packet.options[50] = 4;
    offer_packet.options[51] = 255;
    offer_packet.options[52] = 255;
    offer_packet.options[53] = 255;
    offer_packet.options[54] = 255;

    // fill end
    offer_packet.options[255] = 255;

    /* the IP address we're requesting */
    if(request_specific_address==TRUE){
        offer_packet.options[7]=DHCP_OPTION_REQUESTED_ADDRESS;
        offer_packet.options[8]='\x04';
        memcpy(&offer_packet.options[9],&requested_address,sizeof(requested_address));
    }
    
    /* send the DHCPOFFER packet to broadcast address */
    sockaddr_client.sin_family=AF_INET;
    sockaddr_client.sin_port=htons(DHCP_CLIENT_PORT);
    inet_aton(spoofing_ip, &(sockaddr_client.sin_addr.s_addr));
    inet_aton(this_ip, &offer_packet.yiaddr);
    sockaddr_client.sin_addr.s_addr = inet_addr(spoofing_ip);
    // sockaddr_client.sin_addr.s_addr = inet_aton(spoofing_ip);//INADDR_BROADCAST;
    // sockaddr_client.sin_addr.s_addr = ((in_addr_t) 0xe6f3820a);//0x1082f3e6); // 0xe6f38210 
    // sockaddr_client.sin_addr.s_addr = ((in_addr_t) 0xe6f5820B);
    inet_pton(AF_INET, spoofing_ip, &sockaddr_client.sin_addr.s_addr);

    bzero(&sockaddr_client.sin_zero,sizeof(sockaddr_client.sin_zero));


    if (verbose) {
        printf("DHCPOFFER to %s port %d\n",inet_ntoa(sockaddr_client.sin_addr),ntohs(sockaddr_client.sin_port));
        printf("DHCPOFFER XID: %lu (0x%X)\n",(unsigned long) ntohl(offer_packet.xid),ntohl(offer_packet.xid));
        printf("DHCDISCOVER ciaddr:  %s\n",inet_ntoa(offer_packet.ciaddr));
        printf("DHCDISCOVER yiaddr:  %s\n",inet_ntoa(offer_packet.yiaddr));
        printf("DHCDISCOVER siaddr:  %s\n",inet_ntoa(offer_packet.siaddr));
        printf("DHCDISCOVER giaddr:  %s\n",inet_ntoa(offer_packet.giaddr));
    }

    /* send the DHCPOFFER packet out */
    send_dhcp_packet(&offer_packet, sizeof(offer_packet), sock, &sockaddr_client);

    if (verbose) 
        printf("\n\n");

    return OK;
}


int send_dhcp_ack(int sock){
    dhcp_packet ack_packet;
    struct sockaddr_in sockaddr_client;


    /* clear the packet data structure */
    bzero(&ack_packet,sizeof(ack_packet));


    /* boot request flag (backward compatible with BOOTP servers) */
    ack_packet.op=BOOTREPLY;

    /* hardware address type */
    ack_packet.htype=ETHERNET_HARDWARE_ADDRESS;

    /* length of our hardware address */
    ack_packet.hlen=ETHERNET_HARDWARE_ADDRESS_LENGTH;

    ack_packet.hops=0;

    /* shold get the xid from CLIENT DISCOVER */
    packet_xid=123;
    ack_packet.xid=htonl(packet_xid);

    /**** WHAT THE HECK IS UP WITH THIS?!?  IF I DON'T MAKE THIS CALL, ONLY ONE SERVER RESPONSE IS PROCESSED!!!! ****/
    /* downright bizzarre... */
    ntohl(ack_packet.xid);

    /*ack_packet.secs=htons(65535);*/
    ack_packet.secs=0xFF;

    /* tell server it should broadcast its response */ 
    ack_packet.flags=htons(DHCP_UNICAST_FLAG);

    /* Set client address*/
    inet_aton("0.0.0.0", &ack_packet.ciaddr);

    /* Set sender (server) address*/
    inet_aton(this_ip, &ack_packet.yiaddr);

    struct sockaddr_in sa;
    char buffer[INET_ADDRSTRLEN];
    inet_ntop( AF_INET, &ack_packet.yiaddr, buffer, sizeof( buffer ));

    /* Set next server address*/
    inet_aton("0.0.0.0", &ack_packet.siaddr);

    /* Set relay agent address*/
    inet_aton("0.0.0.0", &ack_packet.giaddr);

    /* our hardware address */
    memcpy(ack_packet.chaddr, client_hardware_address, ETHERNET_HARDWARE_ADDRESS_LENGTH);

    /* first four bytes of options field is magic cookie (as per RFC 2132) */
    ack_packet.options[0]='\x63';
    ack_packet.options[1]='\x82';
    ack_packet.options[2]='\x53';
    ack_packet.options[3]='\x63';

    /* DHCP message type is embedded in options field */
    ack_packet.options[4]=DHCP_OPTION_MESSAGE_TYPE;    /* DHCP message type option identifier */
    ack_packet.options[5]='\x01';               /* DHCP message option length in bytes */
    ack_packet.options[6]=DHCPACK;

    struct in_addr *server_ip = malloc(sizeof (struct in_addr));
    inet_aton(this_ip, server_ip);

    // fill dhcp renewal time (58)
    ack_packet.options[7]  = 58; 
    ack_packet.options[8]  = 4; 
    ack_packet.options[9]  = 0; 
    ack_packet.options[10] = 1; 
    ack_packet.options[11] = 56; 
    ack_packet.options[12] = 128; 

    // fill dhcp rebinding time (59)
    ack_packet.options[13] = 59;
    ack_packet.options[14] = 4;
    ack_packet.options[15] = 0;
    ack_packet.options[16] = 1;
    ack_packet.options[17] = 56;
    ack_packet.options[18] = 128;

    // fill dhcp lease time (51)
    ack_packet.options[19] = 51;
    ack_packet.options[20] = 4;
    ack_packet.options[21] = 0;
    ack_packet.options[22] = 1;
    ack_packet.options[23] = 56;
    ack_packet.options[24] = 128;
    
    // fill dhcp server identifier (54)
    ack_packet.options[25] = 54;
    ack_packet.options[26] = 4;
    ack_packet.options[27] = server_ip->s_addr; 
    ack_packet.options[28] = server_ip->s_addr >> 8;
    ack_packet.options[29] = server_ip->s_addr >> 16;
    ack_packet.options[30] = server_ip->s_addr >> 24;

    // fill dhcp subnet mask (1)
    ack_packet.options[31] = 1;
    ack_packet.options[32] = 4;
    ack_packet.options[33] = this_subnet_mask[0];
    ack_packet.options[34] = this_subnet_mask[1];
    ack_packet.options[35] = this_subnet_mask[2];
    ack_packet.options[36] = this_subnet_mask[3];
     
    // fill dhcp router
    ack_packet.options[37] = 3;
    ack_packet.options[38] = 4;
    ack_packet.options[39] = server_ip->s_addr;
    ack_packet.options[40] = server_ip->s_addr >> 8;
    ack_packet.options[41] = server_ip->s_addr >> 16;
    ack_packet.options[42] = server_ip->s_addr >> 24;

    // fill dhcp dns
    // se usar size ([32]) como 8 da para enviar 2 dns servers
    ack_packet.options[43] = 6;
    ack_packet.options[44] = 4;
    ack_packet.options[45] = server_ip->s_addr;
    ack_packet.options[46] = server_ip->s_addr >> 8;
    ack_packet.options[47] = server_ip->s_addr >> 16;
    ack_packet.options[48] = server_ip->s_addr >> 24;

    // fill dhcp broadcast
    ack_packet.options[49] = 28;
    ack_packet.options[50] = 4;
    ack_packet.options[51] = 255;
    ack_packet.options[52] = 255;
    ack_packet.options[53] = 255;
    ack_packet.options[54] = 255;

    // fill end
    ack_packet.options[255] = 255;

    /* the IP address we're requesting */
    if(request_specific_address==TRUE){
        ack_packet.options[7]=DHCP_OPTION_REQUESTED_ADDRESS;
        ack_packet.options[8]='\x04';
        memcpy(&ack_packet.options[9],&requested_address,sizeof(requested_address));
    }
    
    /* send the DHCPOFFER packet to broadcast address */
    sockaddr_client.sin_family=AF_INET;
    sockaddr_client.sin_port=htons(DHCP_CLIENT_PORT);
    // sockaddr_client.sin_addr.s_addr=INADDR_BROADCAST;
    inet_pton(AF_INET, spoofing_ip, &sockaddr_client.sin_addr.s_addr);

    bzero(&sockaddr_client.sin_zero,sizeof(sockaddr_client.sin_zero));


    if (verbose) {
        printf("DHCPOFFER to %s port %d\n",inet_ntoa(sockaddr_client.sin_addr),ntohs(sockaddr_client.sin_port));
        printf("DHCPOFFER XID: %lu (0x%X)\n",(unsigned long) ntohl(ack_packet.xid),ntohl(ack_packet.xid));
        printf("DHCDISCOVER ciaddr:  %s\n",inet_ntoa(ack_packet.ciaddr));
        printf("DHCDISCOVER yiaddr:  %s\n",inet_ntoa(ack_packet.yiaddr));
        printf("DHCDISCOVER siaddr:  %s\n",inet_ntoa(ack_packet.siaddr));
        printf("DHCDISCOVER giaddr:  %s\n",inet_ntoa(ack_packet.giaddr));
    }

    /* send the DHCPOFFER packet out */
    send_dhcp_packet(&ack_packet,sizeof(ack_packet),sock,&sockaddr_client);

    if (verbose) 
        printf("\n\n");

    return OK;
}
