/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
/* not for test git*/

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#define ICMP_TYPE_REPLY 0
#define ICMP_TYPE_DEST_UNREACHABLE 3
#define ICMP_TYPE_REQUEST 8
#define ICMP_TYPE_TIME_EXCEED 11

#define ICMP_CODE_ZERO 0
#define ICMP_CODE_ONE 1
#define ICMP_CODE_THREE 3


struct sr_if * sr_retrieve_router_interface(struct  sr_instance* sr, uint32_t target_ip);

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
	
	/*INITIAL NAT HERE???? */
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
    
    printf("*** -> Received packet of length %d \n",len);

    /* print_hdr_eth(packet); */

    /* Check ethertype of packet */
    uint16_t ethtype = ethertype(packet);
    unsigned int ethAddressHeaderLength = sizeof(sr_ethernet_hdr_t);

    if ( ethtype == ethertype_ip) 
    {
        printf("==============================================\n");
        printf("==============================================\n");
        printf("INFO: Recieved an ip packet \n");

        /* Begin sanity checking the packet */
        /* Check that length is at least enough to contain a minimal ip header and an ethernet header. */
        if (len < sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t))
        {
            printf("ERROR: Ethernet frame did not meet minimum Ethernet + IP length. Dropping. \n");
            return;
        }


        sr_ip_hdr_t * ipHeader = (sr_ip_hdr_t *) (packet + ethAddressHeaderLength);
        if (len < sizeof(sr_ethernet_hdr_t) + ipHeader->ip_hl*4)
        {
            printf("ERROR: Ethernet frame did not meet minimum Ethernet + IP calculated length. Dropping. \n");
            return;
        }          
        uint16_t expected_ip_cksum;
        uint16_t received_ip_cksum;
        /* Validate checksum. */
        received_ip_cksum = ipHeader->ip_sum;
        ipHeader->ip_sum = 0;
        expected_ip_cksum = cksum(ipHeader, ipHeader->ip_hl*4);
        if (expected_ip_cksum != received_ip_cksum) 
        {
            printf("ERROR: IP packet checksum. Dropping. \n");
            return;
        }
        /* End of IP packet checking*/
        
        /* Now we have two choices: The packect is destined for one of the router's interfeaces or for somewhere else. 
        First see if we can match one of our interfaces */
        struct sr_if * destination_if = sr_retrieve_router_interface(sr, ipHeader->ip_dst);
        if (destination_if) /*Successfuly matched the IP packet's destination to one of the router's interfaces*/
        {
            printf("INFO: Packet is destined for one of the router's interface\n");
            if(ipHeader->ip_p == ip_protocol_icmp) 
            {/* check if recieved ip packet contains an ICMP header */

                printf("INFO: Packet contained an ICMP header\n");

                /* Begin ICMP Header sanity check */
                uint16_t icmp_expected_cksum;
                uint16_t icmp_received_cksum;
                sr_icmp_hdr_t * icmpHeader = (sr_icmp_hdr_t *)(packet + ethAddressHeaderLength + sizeof(sr_ip_hdr_t));
    
                /* Validate the checksum. */
                icmp_received_cksum = icmpHeader->icmp_sum;
                icmpHeader->icmp_sum = 0;
                icmp_expected_cksum = cksum(icmpHeader, ntohs(ipHeader->ip_len) - ipHeader->ip_hl*4);

                if (icmp_received_cksum != icmp_expected_cksum)
                {
                    printf("ERROR: ICMP packet checksum. Dropping. \n");
                    return;
                }
                /* End ICMP sanity check */
    
                /* If the ICMP type is an echo request reply to it. */
                if (icmpHeader->icmp_type == ICMP_TYPE_REQUEST) 
                {
                    /* Send icmp echo reply. */
                    printf("INFO: ICMP packet contained an echo request. Constructing reply...\n");
                    
                    uint32_t temp;
                    temp = ipHeader->ip_dst;

                    ipHeader->ip_dst = ipHeader->ip_src;
                    ipHeader->ip_src = temp;
                    icmpHeader->icmp_sum = 0;
                    icmpHeader->icmp_code = ICMP_CODE_ZERO;
                    icmpHeader->icmp_type = ICMP_TYPE_REPLY;
                    icmpHeader->icmp_sum = cksum(icmpHeader, ntohs(ipHeader->ip_len) - ipHeader->ip_hl*4);

                    sr_send_icmp(sr, (uint8_t *)ipHeader, ntohs(ipHeader->ip_len), ICMP_TYPE_REPLY, ICMP_CODE_ZERO);
                    return;
                }
                printf("ERROR: ICMP packet was not an echo request. Dropping. \n");
                return;
            }/* End for IP packet is an ICMP packet.*/
            else if (ipHeader->ip_p == ip_protocol_tcp || ipHeader->ip_p == ip_protocol_udp)
            {   /*Port unreachable (type 3, code 3) */
                
                sr_send_icmp(sr, (uint8_t *)ipHeader, ntohs(ipHeader->ip_len), ICMP_TYPE_DEST_UNREACHABLE, ICMP_CODE_THREE);
            }
            else
            {
                /* unknown protocol type, error*/
                printf("Error: Unknown IP protocol type. Dropping.\n");
                return;
            }
        } /* end for ip packet destination is for router interface */
        else
        {  
            printf("INFO: Beginning forwarding logic for IP packet.\n");
            uint8_t *forward_ip_packet;
            unsigned int ip_packet_len;

            /* Update the ip header ttl. */
            ipHeader->ip_ttl--;
    
            /* If the ttl is equal to 0, send an ICMP Time exceeded response and return. */
            ip_packet_len = ntohs(ipHeader->ip_len);;
            if (ipHeader->ip_ttl == 0) 
            {
                sr_send_icmp(sr, (uint8_t *)ipHeader, ip_packet_len, ICMP_TYPE_TIME_EXCEED, ICMP_CODE_ZERO);
                return;
            }
    
            /* Update the checksum. */
            ipHeader->ip_sum = 0;
            ipHeader->ip_sum = cksum(ipHeader, ipHeader->ip_hl*4);

            sr_send_ethernet_packet(sr, ipHeader, ip_packet_len, ipHeader->ip_dst, 0, ethertype_ip);
            return;
        }
        
    }  /* end for IP packet*/ 
    else if (ethtype == ethertype_arp) 
    {

        printf("==============================================\n");
        printf("==============================================\n");
        printf("==============================================\n");
        printf("INFO: Recieved an ARP packet.\n");

        struct sr_arpreq *arp_req;

        sr_ethernet_hdr_t *ethHeader = (sr_ethernet_hdr_t *)packet;
        sr_arp_hdr_t *arpHeader = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
        

        struct sr_if * incoming_if;
        incoming_if = sr_get_interface(sr, interface);
        struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, arpHeader->ar_sip);

        if(arp_entry != 0)
        {
            printf("INFO: ARP cache already contains IP information contained in ARP packet.\n "); 
        }
        else
        {
            printf("INFO: ARP packet contained new IP-MAC mapping. Adding it to the cache. \n");
            arp_req = sr_arpcache_insert(&sr->cache, arpHeader->ar_sha, arpHeader->ar_sip);
        }

        /* Handle a request. */
        if (ntohs(arpHeader->ar_op) == arp_op_request) 
        {
            printf("INFO: ARP packet contained a request. Beginning reply logic. \n");

            int pos = 0;
            arpHeader->ar_op = ntohs(2);
            memcpy(arpHeader->ar_tha, arpHeader->ar_sha, ETHER_ADDR_LEN);
            memcpy(arpHeader->ar_sha, incoming_if->addr, ETHER_ADDR_LEN);
            arpHeader->ar_tip = arpHeader->ar_sip;
            arpHeader->ar_sip = incoming_if->ip;

            memcpy(ethHeader->ether_dhost, ethHeader->ether_shost, ETHER_ADDR_LEN);
            memcpy(ethHeader->ether_shost, incoming_if->addr, ETHER_ADDR_LEN);

            sr_send_packet(sr, packet, len, interface);
            return;
        }
        else if (ntohs(arpHeader->ar_op) == arp_op_reply) 
        {
            printf("INFO: Recieved an ARP reply. Sending packets waiting on that ARP request.\n");
            struct sr_packet *cur;
            struct sr_ip_hdr *ip_hdr;
            
            cur = arp_req->packets;
            
            while (cur != 0) 
            {
                ip_hdr = (struct sr_ip_hdr *)cur->buf;
                sr_send_ethernet_packet(sr,  cur->buf,  cur->len,  ip_hdr->ip_dst, 0,  ethertype_ip);
                cur = cur->next;
            }
            return;     
        }   
    }

}/* end sr_ForwardPacket */


/*---------------------------------------------------------------------
 * Method: sr_retrieve_router_interface(struct  sr_instance* sr, uint32_t target_ip)
 * Scope:  Global
 *
 * Iterates thought the router's interfaces and returns the first to match
 * the target_ip. If no match is found returns NULL
 *
 *---------------------------------------------------------------------*/
struct sr_if* sr_retrieve_router_interface(struct  sr_instance* sr, uint32_t target_ip)
{
    struct sr_if* ip_interface;
    ip_interface = sr->if_list;

    while(ip_interface)
    {
        if(target_ip == ip_interface->ip)
            return ip_interface;
        ip_interface = ip_interface->next;
    }
    return NULL;
}

/*---------------------------------------------------------------------
 * Method: sr_longest_prefix_match(struct sr_instance* sr, struct in_addr addr)
 * Scope:  Global
 *
 * Takes: in_addr addr -> a valid ip address.
 *
 * Returns: sr_rt * -> the routing table entry with the longest matching IP 
 *                     address prefix
 *
 *---------------------------------------------------------------------*/
struct sr_rt *sr_longest_prefix_match(struct sr_instance* sr, struct in_addr addr)
{
    struct sr_rt* lpm = NULL;
    uint32_t lpm_len = 0;
    struct sr_rt* rt = sr->routing_table;
  
    while( rt != 0 ) 
    {
        if (((rt->dest.s_addr & rt->mask.s_addr) == (addr.s_addr & rt->mask.s_addr)) &&
              (lpm_len <= rt->mask.s_addr)) 
        {
              
            lpm_len = rt->mask.s_addr;
            lpm = rt;
        }
        
        rt = rt->next;
    }
    
    return lpm;
}

/*---------------------------------------------------------------------
 * Method: sr_send_ethernet_packet(struct sr_instance* sr,
 *                          uint8_t *packet,
 *                          unsigned int len,
 *                          uint32_t destination_ip,
 *                          int icmp_error_type,
 *                          enum sr_ethertype eth_type)
 * Scope:  Global
 *
 * This general method is used to send IP packets. The method chooses
 * the correct router interface to send the packet out on. The packet
 * variable is not freed.
 *
 *---------------------------------------------------------------------*/
void sr_send_ethernet_packet(struct sr_instance* sr,
                            uint8_t *packet,
                            unsigned int len,
                            uint32_t destination_ip,
                            int icmp_error_type,
                            enum sr_ethertype eth_type)
{
    
    printf("INFO: Beginning logic to send ethernet packet.\n");
    struct sr_rt *rt;
    struct sr_arpreq *arp_req;
    struct sr_ethernet_hdr eth_hdr;
    struct sr_arpentry *arp_entry;

    uint8_t *ip_pkt;
    uint8_t *eth_pkt;
    struct sr_if *outgoing_interface;
    
    unsigned int eth_pkt_len;
    
    /* Look up shortest prefix match in the routing table. */
    struct in_addr dest_ip_ad;
    dest_ip_ad.s_addr = destination_ip;
    rt = sr_longest_prefix_match(sr, dest_ip_ad);
    if (!rt) {
        printf("ERROR: Could not find an appropriate egress interface. Dropping. Sending ICMP type 3 code 0.\n");
        sr_send_icmp(sr, packet, len, ICMP_TYPE_DEST_UNREACHABLE, ICMP_CODE_ZERO);
        return;
    }

    /* Fetch the appropriate outgoing interface.  */
    outgoing_interface = sr_get_interface(sr, rt->interface);

    /* If there is already an arp entry in the cache, send now. */  
    arp_entry = sr_arpcache_lookup(&sr->cache, rt->gw.s_addr);
    if (arp_entry || eth_type == ethertype_arp) {
        printf("INFO: Destination was found in the arpcache. \n");

        /* Create the ethernet packet.*/
        eth_pkt_len = len + sizeof(sr_ethernet_hdr_t);
        eth_hdr.ether_type = htons(eth_type);

        /* Destination is broadcast if it is an arp request.*/
        if (eth_type == ethertype_arp && ((struct sr_arp_hdr *)packet)->ar_op == htons(arp_op_request))
            memset(eth_hdr.ether_dhost, 255, ETHER_ADDR_LEN);
        else
            memcpy(eth_hdr.ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        
        memcpy(eth_hdr.ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
        
        
        eth_pkt = malloc(eth_pkt_len);
        memcpy(eth_pkt, &eth_hdr, sizeof(eth_hdr));
        memcpy(eth_pkt + sizeof(eth_hdr), packet, len);
        

        sr_send_packet(sr, eth_pkt, eth_pkt_len, outgoing_interface);
        
        free(eth_pkt);
        free(arp_entry);
    
    } else { /* Otherwise add it to the arp request queue. */
        printf("INFO: Destination was not found in the arpcache. Adding packet to queue.\n");
        ip_pkt = malloc(len);
        memcpy(ip_pkt, packet, len);
        arp_req = sr_arpcache_queuereq(&sr->cache, rt->gw.s_addr, ip_pkt, len, outgoing_interface);
        free(ip_pkt);
        sr_arpreq_handler(sr, arp_req);
    }
    
}


/*---------------------------------------------------------------------
 * This function sends an icmp with the type and code
 * parameter: packet is an IP packet, len is its length
 *---------------------------------------------------------------------*/
void sr_send_icmp(struct sr_instance* sr, uint8_t *packet, unsigned int len, uint8_t type, uint8_t code)
{


    sr_ip_hdr_t* ipHeader;
    sr_icmp_hdr_t* icmpHeader;

    ipHeader = (sr_ip_hdr_t *)packet;
    icmpHeader =(sr_icmp_hdr_t*) (ipHeader + ipHeader->ip_hl * 4);
    
    
    uint16_t total_len;

   
    sr_icmp_hdr_t* IcmpHeaderCopy;
    uint8_t *new_pkt;


    /* Destination unreachable message or TTL exceeded. */
    
    if ((type == ICMP_TYPE_DEST_UNREACHABLE ) || (type == ICMP_TYPE_TIME_EXCEED))
    {

        printf("============== Now we enter type 3 icmp function\n on interface:");

        /*
        printf("============== Following is current ipheader info\n");
        print_hdr_ip((uint8_t*)ipHeader);
        */
        /*first create new icmp3 header*/
        struct sr_icmp_t3_hdr icmp3Header;
        
        icmp3Header.icmp_type = type;
        icmp3Header.icmp_code = code;
        icmp3Header.icmp_sum  = 0;
        icmp3Header.unused    = 0;
        icmp3Header.next_mtu  = 0;
        memcpy(icmp3Header.data,ipHeader,28);
        icmp3Header.icmp_sum = cksum(&icmp3Header,sizeof(icmp3Header));
        printf("===========Following is old ip packet\n");
        print_hdr_ip((uint8_t*)ipHeader);
     
        printf("===========start to create new ip header and ip packet\n");

        struct sr_ip_hdr ip_hdr;
        
        ip_hdr.ip_hl = 5;
        ip_hdr.ip_v = 4;
        ip_hdr.ip_tos = 0;
        ip_hdr.ip_id = ipHeader->ip_id;
        ip_hdr.ip_off = htons(0x4000);
        ip_hdr.ip_ttl = 64;
        ip_hdr.ip_p = ip_protocol_icmp;
        ip_hdr.ip_sum = 0;
        ip_hdr.ip_dst = ipHeader->ip_src;
        printf("===========the incoming interface ip is \n"  );
        
        struct in_addr dest_ip_ad;
        dest_ip_ad.s_addr = ipHeader->ip_src;
        
        struct sr_rt *rt = sr_longest_prefix_match(sr, dest_ip_ad);
        
        struct sr_if *  outgoing_interface = sr_get_interface(sr, rt->interface);
        


        ip_hdr.ip_src = outgoing_interface->ip;  


        printf("===========EXISTANT \n"  );
        ip_hdr.ip_len = htons( sizeof(ip_hdr) + sizeof(icmp3Header));

        ip_hdr.ip_sum = cksum(&ip_hdr, sizeof(ip_hdr));

        printf("============== new ip header info\n");
        print_hdr_ip((uint8_t*)&ip_hdr);
        
        printf("============== new icmp header info\n");
        print_hdr_icmp((uint8_t*)&icmp3Header);
        
        printf("============== new icmp header info\n");
        print_hdr_icmp((uint8_t*)&icmp3Header);
        
           
            
        total_len = sizeof(ip_hdr) + sizeof(icmp3Header);
        printf("========total length of new ip packet is %d\n", total_len);
            
        new_pkt = malloc(total_len);
        memcpy(new_pkt, &ip_hdr, sizeof(ip_hdr));           /*copy the first 20 bytes ip header info to the new packet*/

        memcpy(new_pkt + sizeof(ip_hdr), &icmp3Header, sizeof(icmp3Header));

        /*
        printf("========Before we send out the packet, check ip header again\n");
        print_hdr_ip((uint8_t*)new_pkt);
        */
        
        sr_send_ethernet_packet(sr, new_pkt, total_len, ip_hdr.ip_dst, 1, ethertype_ip);
        return;
    
    } 
    else if (type == 0) {

        printf("Ready to process icmp echo_reply\n");

        /* Update ICMP header fields */
        icmpHeader->icmp_sum = 0;
        icmpHeader->icmp_code = code;
        icmpHeader->icmp_type = type;
        icmpHeader->icmp_sum = cksum(icmpHeader, ntohs(ipHeader->ip_len) - ipHeader->ip_hl*4);
    
       
        ipHeader->ip_sum = 0;   
        ipHeader->ip_sum = cksum(ipHeader, ipHeader->ip_hl*4);


        /* Allocate a copy of this packet. */
        total_len = ntohs(ipHeader->ip_len);
        new_pkt = malloc(total_len);
        memcpy(new_pkt, packet, total_len);
        
        
    }
    
    
    printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^ in the function sr_send_icmp send packet\n");
    /* Encapsulate and send */
    sr_send_ethernet_packet(sr, new_pkt, len, ipHeader->ip_dst, 0, ethertype_ip);
    
}
