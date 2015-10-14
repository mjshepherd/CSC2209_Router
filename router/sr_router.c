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
/* add this for line for test git*/

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


void set_ethernet_header(sr_ethernet_hdr_t * ethHeader, uint8_t * destination_address, uint8_t * source_address);
struct sr_if * retrieveRouterInterface(struct  sr_instance* sr, uint32_t destIP);
int destinationIPHasRoute();
uint32_t ck_lpm(uint32_t rt_dest, uint32_t mask, uint32_t dest);


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

    if ( ethtype == ethertype_ip) 
    {
        printf("==============================================\n");
        printf("==============================================\n");
        printf("==============================================\n");
        printf("Recieved an ip packet! \n");

        /* Return if it is not a valid ip packet */

        /* Check that length is at least enough to contain a minimal ip header and an ethernet header. */
        if (len < sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t))
        {
            printf("IP packet length is not enough long \n");
            return;
        }
        
        uint16_t expected_cksum;
        uint16_t received_cksum;
    


        /* Check that the header length specified makes a little sense before computing the checksum. */
        /* NOTE: is this necessary? */
        unsigned int ethAddressHeaderLength = sizeof(sr_ethernet_hdr_t);
        sr_ip_hdr_t * ipHeader = (sr_ip_hdr_t *) (packet + ethAddressHeaderLength);
        print_hdr_ip((uint8_t *)ipHeader);
    
        if (len < sizeof(sr_ethernet_hdr_t) + ipHeader->ip_hl*4)
            return;
    
        printf("Starting to check checksum value\n");
        /* Validate checksum. */
    
        received_cksum = ipHeader->ip_sum;
        ipHeader->ip_sum = 0;
        expected_cksum = cksum(ipHeader, ipHeader->ip_hl*4);
        printf("Received IP checksum value = %d\n", received_cksum);
        printf("Computed IP checksum chechsum value = %d\n", expected_cksum);

        if (expected_cksum != received_cksum)
            return;
        
        /* Now we have two choices: The packect is destined for one of the router's interfeaces or for somewhere else. First see if we can match one of our interfaces */
        struct sr_if * destination_if = retrieveRouterInterface(sr, ipHeader->ip_dst);
        if (destination_if) /*Successfuly matched the IP packet's destination to one of the router's interfaces*/
        {
            if(ipHeader->ip_p == ip_protocol_icmp) 
            {/* check if recieved ip packet contains an ICMP header */

                printf("========= Recieved ICMP packet destined for router's interface\n");

                /* Validate icmp. Drop if it not an echo request or bad checksum. */
                uint16_t icmp_expected_cksum;
                uint16_t icmp_received_cksum;

                sr_icmp_hdr_t * icmpHeader = (sr_icmp_hdr_t *)(packet + ethAddressHeaderLength + sizeof(sr_ip_hdr_t));
                printf("ICMP header is: \n");
                print_hdr_icmp((uint8_t *)icmpHeader);
    
                /* Validate the checksum. */
                icmp_received_cksum = icmpHeader->icmp_sum;
                icmpHeader->icmp_sum = 0;
                icmp_expected_cksum = cksum(icmpHeader, ntohs(ipHeader->ip_len) - ipHeader->ip_hl*4);
                
                printf("Recieved ICMP checksum value = %d\n", icmp_received_cksum);
                printf("Computed ICMP checksum value = %d\n", icmp_expected_cksum);

                if (icmp_received_cksum != icmp_expected_cksum)
                {
                    printf("ICMP packet did not pass checksum! Dropping. \n");
                    return;
                }
                else
                {
                    printf("ICMP checksum is ok \n");
                }
    
                /* If the ICMP type is an echo request reply to it. Otherwise do nothing. */
                if (icmpHeader->icmp_type == 8) 
                {
                    /* Send icmp echo reply. */
                    
                    sr_send_icmp(sr, (uint8_t *)ipHeader, ntohs(ipHeader->ip_len), 0, 0, destination_if, ipHeader->ip_src);
                    return;
                }
            }/* End for Ip packet is an ICMP packet.*/
            else if (ipHeader->ip_p == ip_protocol_tcp || ipHeader->ip_p == ip_protocol_udp)
            {   /*Port unreachable (type 3, code 3) */
                sr_send_icmp(sr, (uint8_t *)ipHeader, ntohs(ipHeader->ip_len), 3, 3);
            }
            else
            {
                /* unknown protocol type, error*/
                printf("Unknown IP protocol type, dropping packet.\n");
                return;
            }
        }    /* end for Ip packet destination is for router interface */
        else if(destinationIPHasRoute())
        {  
            printf("222222222222222222\n");
            uint8_t *fwd_ip_pkt;
            unsigned int len;

            /* Update the ip header ttl. */
            ipHeader->ip_ttl--;
    
            /* If the ttl is equal to 0, send an ICMP Time exceeded response and return. */
            len = ntohs(ipHeader->ip_len);;
            if (ipHeader->ip_ttl == 0) 
            {
                sr_send_icmp(sr, (uint8_t *)ipHeader, len, 11, 0);
                return;
            }
    
            /* Update the checksum. */
            ipHeader->ip_sum = 0;
            ipHeader->ip_sum = cksum(ipHeader, ipHeader->ip_hl*4);

            /* Make a copy, encapsulate and send it on. */
            
            fwd_ip_pkt = malloc(len);
            memcpy(fwd_ip_pkt, ipHeader, len);
            sr_encap_and_send_pkt(sr, fwd_ip_pkt, len, ipHeader->ip_dst, 1, ethertype_ip);
            free(fwd_ip_pkt);
            
        }
        else  
        {  /*  Here IP can not be routed, Destination net unreachable (type 3, code 0) */
            printf("Could not resolve IP destination\n");
        }
        /* icmpHeader->icmp_sum = 0; */
        /*
        sr_ip_hdr_t* IpHeader =  (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
        */

    }  /* end for IP packet*/ 
    else if (ethtype == ethertype_arp) 
    {

        printf("==============================================\n");
        printf("==============================================\n");
        printf("==============================================\n");
        printf("Recieved an ARP packet! \n");
        print_hdrs(packet, len);
        
        int pos = 0;
        sr_ethernet_hdr_t *ethHeader = (sr_ethernet_hdr_t *)packet;
        sr_arp_hdr_t *arpHeader = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
        struct sr_if * iface;
        iface = sr_get_interface(sr, interface);

        
        arpHeader->ar_op = ntohs(2);
        for (pos = 0; pos < ETHER_ADDR_LEN; pos++) {
          arpHeader->ar_tha[pos] = arpHeader->ar_sha[pos];
        }
        arpHeader->ar_tip = arpHeader->ar_sip;
        for (pos = 0; pos < ETHER_ADDR_LEN; pos++) {
          arpHeader->ar_sha[pos] = iface->addr[pos];
        }
        arpHeader->ar_sip = iface->ip;

        set_ethernet_header(ethHeader, ethHeader->ether_shost, iface->addr);

        sr_send_packet(sr, packet, len, interface);
    
    }


}/* end sr_ForwardPacket */


void set_ethernet_header(sr_ethernet_hdr_t * ethHeader, uint8_t * destination_address, uint8_t * source_address)
{
      int pos = 0;
      for (pos = 0; pos < ETHER_ADDR_LEN; pos++) {
        ethHeader->ether_dhost[pos] = destination_address[pos];
      }

      for (pos = 0; pos < ETHER_ADDR_LEN; pos++) {
        ethHeader->ether_shost[pos] = source_address[pos];
      }
}


struct sr_if* retrieveRouterInterface(struct  sr_instance* sr, uint32_t destIP)
{

    struct sr_if* ip_interface;
    ip_interface = sr->if_list;

    printf("Starting looking for interface========\n");
    printf("Trying to match : %x\n", destIP);
    while(ip_interface)
    {
        printf("Against.. : %x\n", ip_interface->ip);

        if(destIP == ip_interface->ip)
        {
            printf("Found a router interface matching destination IP\n");
            return ip_interface;
        }
        ip_interface = ip_interface->next;
    }
    printf("Did not find a matching router interface!\n");
    return NULL;

}


int destinationIPHasRoute()
{
    return 0;
}

uint32_t ck_lpm(uint32_t rt_dest, uint32_t mask, uint32_t dest) {
  int j = 31;
  while (j > -1 && ((mask >> j) & 1)) {
    j--;
  }
  int mask_number = 31 - j;
  int i = mask_number;
  while (i) {
      int rt_dest_bit = (ntohl(rt_dest) >> i) & 1;
      int dest_bit = (dest >> i) & 1;

      if (rt_dest_bit != dest_bit) {
        return 0;
      }
      i--;
  }
  return mask_number;
}


/*---------------------------------------------------------------------
 * Method:sr_longest_prefix_match(struct sr_instance* sr, struct in_addr)
 *
 * Look up the longest prefix match in the routing table. Return the 
 * associated struct sr_rt.
 *---------------------------------------------------------------------*/
struct sr_rt *sr_longest_prefix_match(struct sr_instance* sr, struct in_addr addr)
{
    struct sr_rt* rt;
    struct sr_rt* lpm;
    uint32_t lpm_len;
    
    printf("Trying to match the ip address: \n");
    print_addr_ip(addr);
    rt = sr->routing_table;
    lpm_len = 0;
    lpm = NULL;
    
    /* Iterate through the interfaces and compare the masked addresses. If they are equal
     * then we found a match. We know it is longest if the netmask we used is greater
     * than the one used for the previous match. */
    while(rt != 0) {
        printf("With the ip address:  \n");
        print_addr_ip(rt->dest);
        if (((rt->dest.s_addr & rt->mask.s_addr) == (addr.s_addr & rt->mask.s_addr)) &&
              (lpm_len <= rt->mask.s_addr)) {
              
            lpm_len = rt->mask.s_addr;
            lpm = rt;
        }
        
        rt = rt->next;
    }
    
    return lpm;
}


/*---------------------------------------------------------------------
 * Method: sr_encap_and_send_pkt(struct sr_instance* sr, 
 *                                                  uint8_t *packet, 
 *                                                  unsigned int len, 
 *                                              uint32_t dip,
 *                                                  int send_icmp,
 *                                                  sr_ethertype type)
 * Scope:  Global
 *
 * Sends a packet of length len and destination ip address dip, by 
 * looking up the shortest prefix match of the dip (net byte order).
 * If it finds a match, it then checks the arp cache to find the 
 * associated hardware address. If the hardware address is found it 
 * sends it, otherwise it queues the packet and sends an ARP request.
 * If the destination is sill not found, it sends an ICMP host unreachable.
 *
 *---------------------------------------------------------------------*/
void sr_encap_and_send_pkt(struct sr_instance* sr,
                            uint8_t *packet,
                            unsigned int len,
                            uint32_t destination_ip,
                            int send_icmp,
                            enum sr_ethertype eth_type)
{
    printf("============Ready to send packet===================\n");

    struct sr_rt *rt;
    struct sr_arpreq *arp_req;
    struct sr_ethernet_hdr eth_hdr;
    
    struct sr_arpentry *arp_entry;
    
    
    uint8_t *ip_pkt;
    uint8_t *eth_pkt;
    struct sr_if *outgoing_interface;
    
    unsigned int eth_pkt_len;
    
    /* Look up shortest prefix match in your routing table. */
    struct in_addr dest_ip_ad;
    dest_ip_ad.s_addr = destination_ip;
    
    rt = sr_longest_prefix_match(sr, dest_ip_ad);
    
    /* If the entry doesn't exist, send ICMP host unreachable and return if necessary. */
    
    if (!rt) {
        printf("Tried to send packet but no longest matching prefix was found. \n");
        /*
        if (send_icmp)
            sr_send_icmp(sr, packet, len, ICMP_UNREACHABLE_TYPE, ICMP_NET_CODE);
        */
        return;
    }

    /* Fetch the appropriate outgoing interface.  */
    outgoing_interface = sr_get_interface(sr, rt->interface);

    /* If there is already an arp entry in the cache, send now. */  
    arp_entry = sr_arpcache_lookup(&sr->cache, rt->gw.s_addr);
    if (arp_entry || eth_type == ethertype_arp) {
        printf("Destination was found in the arpcache. \n");
        /* Create the ethernet packet.*/
        eth_pkt_len = len + sizeof(sr_ethernet_hdr_t);
        eth_hdr.ether_type = htons(eth_type);
        
        /*   Destination is broadcast if it is an arp request. */
        if (eth_type == ethertype_arp && ((struct sr_arp_hdr *)packet)->ar_op == htons(arp_op_request))
            memset(eth_hdr.ether_dhost, 255, ETHER_ADDR_LEN);
        
        /*   Destination is the arp entry mac if it is an ip packet or and are reply. */
        else
            memcpy(eth_hdr.ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        memcpy(eth_hdr.ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
        
        
        eth_pkt = malloc(eth_pkt_len);
        memcpy(eth_pkt, &eth_hdr, sizeof(eth_hdr));
        memcpy(eth_pkt + sizeof(eth_hdr), packet, len);
        printf("About to call send packet with the following info:\n");
        print_hdrs(eth_pkt, eth_pkt_len);
        printf("Trying to send the above packet on the interface with ip: %s\n", outgoing_interface->name);

        sr_send_packet(sr, eth_pkt, eth_pkt_len, outgoing_interface);
        free(eth_pkt);
        if (arp_entry)
            free(arp_entry);
    
        /* Otherwise add it to the arp request queue. */
    
    } else {
        /*printf("add it to the arp request queue\n");*/
        printf("Destination was not found in the arpcache\n");

        ip_pkt = malloc(len);
        memcpy(ip_pkt, packet, len);
        arp_req = sr_arpcache_queuereq(&sr->cache, rt->gw.s_addr, ip_pkt, len, outgoing_interface);
        free(ip_pkt);
        sr_arpreq_handle(sr, arp_req);
    }
    
}


/*---------------------------------------------------------------------
 * Method: sr_send_icmp(struct sr_instance* sr, 
 *                      uint8_t *packet, 
 *                      unsigned int len,
 *                      uint8_t type,
 *                      uint8_t code)
 * Scope: Global
 *
 * This function sends an icmp of the supplied type and code, using the
 * supplied packet, which is an ip datagram. 
 *
 *---------------------------------------------------------------------*/
void sr_send_icmp(struct sr_instance* sr, uint8_t *packet /*Lent*/, unsigned int len, uint8_t type, uint8_t code, struct sr_if *interface, uint32_t destination_ip)
{
    printf("Now we know ICMP header, IP header, MAC ready to send back\n");
    printf("**************************************************\n");

    
    uint16_t total_len;

    sr_ip_hdr_t* ipHeader;
    sr_icmp_hdr_t* icmpHeader;
    sr_icmp_hdr_t* IcmpHeaderCopy;
    uint8_t *new_pkt;

    ipHeader = (sr_ip_hdr_t *) &packet[sizeof(sr_ethernet_hdr_t)];
    icmpHeader =(sr_icmp_hdr_t*) (ipHeader + ipHeader->ip_hl * 4);
    
    /* Destination unreachable message or TTL exceeded. */
    
    if (type == 3 || type == 11)
    {
        
        /* Update the IP header fields. */
    /*
        error_ip_hdr = (struct sr_ip_hdr *)packet;
        ip_hdr.ip_hl = ICMP_IP_HDR_LEN;
        ip_hdr.ip_v = ip_version_4;
        ip_hdr.ip_tos = 0;
        ip_hdr.ip_id = error_ip_hdr->ip_id;
        ip_hdr.ip_off = htons(IP_DF);
        ip_hdr.ip_ttl = DEFAULT_TTL;
        ip_hdr.ip_p = ip_protocol_icmp;
        ip_hdr.ip_sum = 0;
        ip_hdr.ip_dst = error_ip_hdr->ip_src;
        dst = error_ip_hdr->ip_src;
    
        /* Look up longest prefix match in your routing table. If it doesn't exist, just
         * give up. No use in sending an error message for an error message. */
    /*
        rt = sr_longest_prefix_match(sr, ip_in_addr(ip_hdr.ip_dst));
        if (rt == 0)
            return;
        
        /* Update the source IP to be the outgoing interface's ip address. */
    /*
        interface = sr_get_interface(sr, (const char*)rt->interface);
        ip_hdr.ip_src = interface->ip;
        
        /* Update length: first 8 bytes of original message, original ip header, icmp header
         * and new ip header. */
    /*
        icmp_len = ip_ihl(error_ip_hdr) + ICMP_COPIED_DATAGRAM_DATA_LEN + sizeof(struct sr_icmp_hdr);
        total_len = icmp_len + ICMP_IP_HDR_LEN_BYTES;
        ip_hdr.ip_len = htons(total_len);
        
        /* Update the ip checksum. */
    /*
        ip_hdr.ip_sum = cksum(&ip_hdr, ICMP_IP_HDR_LEN_BYTES);
    
        /* Allocate a packet, copy everything in. */
    /*
        new_pkt = malloc(total_len);
        memcpy(new_pkt, &ip_hdr, ICMP_IP_HDR_LEN_BYTES);
        memcpy(new_pkt + ICMP_IP_HDR_LEN_BYTES, &icmp_hdr, sizeof(struct sr_icmp_hdr));
        memcpy(new_pkt + ICMP_IP_HDR_LEN_BYTES + sizeof(struct sr_icmp_hdr), 
                     error_ip_hdr, 
                     ip_ihl(error_ip_hdr) + ICMP_COPIED_DATAGRAM_DATA_LEN);
        
    /* Echo reply. */
    
    } 
    else if (type == 0) {

        printf("Ready to process icmp echo_reply\n");

        /* Update ICMP header fields */
        icmpHeader->icmp_sum = 0;
        icmpHeader->icmp_code = code;
        icmpHeader->icmp_type = type;
        icmpHeader->icmp_sum = cksum(icmpHeader, ntohs(ipHeader->ip_len) - ipHeader->ip_hl*4);
    
        /* Update IP header fields 
         * Setting TTL to 64
         * Currently not modifying total length or header length
         */
        ipHeader->ip_src = interface->ip;
        ipHeader->ip_ttl = 64;
        ipHeader->ip_p = ip_protocol_icmp;
        ipHeader->ip_dst = destination_ip;
        ipHeader->ip_sum = 0;
        ipHeader->ip_sum = cksum(ipHeader, ipHeader->ip_hl*4);


        /* Allocate a copy of this packet. */
        total_len = ntohs(ipHeader->ip_len);
        new_pkt = malloc(total_len);
        memcpy(new_pkt, packet, total_len);
        
        /* What?
        icmp_len = total_len - 5;
        */
        
    }
    
    
    /* Encapsulate and send */
    sr_encap_and_send_pkt(sr, new_pkt, len, destination_ip, 0, ethertype_ip);
    
}
