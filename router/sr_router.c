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


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


void set_ethernet_header(sr_ethernet_hdr_t * ethHeader, uint8_t * destination_address, uint8_t * source_address);
int destinedForRouterInterface(struct  sr_instance* sr, uint32_t destIP);
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

    // print_hdr_eth(packet);

    /* Check ethertype of packet */
    uint16_t ethtype = ethertype(packet);

    if ( ethtype == ethertype_ip) 
    {
    printf("==============================================\n");
    printf("==============================================\n");
    printf("==============================================\n");
    printf("Recieved an ip packet! \n");

    /* Return if it is not a valid ip packet */
  
    uint16_t expected_cksum;
    uint16_t received_cksum;
  
    /* Check that length is at least enough to contain a minimal ip header and an ethernet header. */ 
    if (len < sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t))
    {
      printf("Ip length is not enough long");
      return;
    }

    /* Check that the header length specified makes a little sense before computing the checksum. */
    unsigned int ethAddressHeaderLength = sizeof(sr_ethernet_hdr_t);
    sr_ip_hdr_t * ipHeader = (sr_ip_hdr_t *) (packet + ethAddressHeaderLength);
    print_hdr_ip(ipHeader);
  
    if (len < sizeof(sr_ethernet_hdr_t) + ipHeader->ip_hl*4)
      return;
  
    printf("Starting to check chechsum value\n");
    /* Validate checksum. */
  
    received_cksum = ipHeader->ip_sum;
    ipHeader->ip_sum = 0;
    expected_cksum = cksum(ipHeader, ipHeader->ip_hl*4);
    printf("Receive check chechsum value = %d\n", received_cksum);
    printf("We compute check chechsum value = %d\n", expected_cksum);

    if (expected_cksum != received_cksum)
      return;
  
    /* Now make sure the length of the entire packet is exactly correct. */
    /*
    if (len != sizeof(struct sr_ethernet_hdr) + ip_len(ip_hdr))
    return 0;
    */
    
  
    if(destinedForRouterInterface(sr, ipHeader->ip_dst)) /*Ip packet destination is for router interface*/
    {

      if(ipHeader->ip_p == ip_protocol_icmp) 
      {/* check if recieved ip packet contains an ICMP header */

        printf("========= I receive a icmp packet for my router interface\n");

        /* Validate icmp. Drop if it not an echo request or bad checksum. */
    
        uint16_t icmp_expected_cksum;
        struct sr_icmp_hdr *icmp_hdr;
        uint16_t icmp_received_cksum;

        sr_icmp_hdr_t * icmpHeader = (sr_icmp_hdr_t *)(packet + ethAddressHeaderLength + sizeof(sr_ip_hdr_t));
        printf("ICMP header is ");
        print_hdr_icmp(icmpHeader);
  
        /* Validate the checksum. */
        icmp_received_cksum = icmpHeader->icmp_sum;
        printf("ICMP chechsum value = %d\n", icmp_received_cksum);
        icmpHeader->icmp_sum = 0;
        icmp_expected_cksum = cksum(icmpHeader, ntohs(ipHeader->ip_len) - ipHeader->ip_hl*4);
        printf("ICMP I compute chechsum value = %d\n", icmp_expected_cksum);

        if (icmp_received_cksum != icmp_expected_cksum)
          printf(" NO GOOD \n");
        else
          printf(" ICMP checksum is ok \n");

  
        /* Make sure it is a icmp echo request. */
        /*  if ((icmp_hdr->icmp_type != ICMP_ECHO_REQUEST_CODE) || (icmp_hdr->icmp_code != ICMP_ECHO_REPLY_CODE))*/
        if (icmpHeader->icmp_type == 8) 
        {
          /* Send icmp echo reply. */
          sr_send_icmp(sr, (uint8_t *)ipHeader, ntohs(ipHeader->ip_len), 0, 0);
        }
      }   /* End for Ip packet is to one of the router interface and it is a ICMP packet.*/
      
      else if (ipHeader->ip_p == ip_protocol_tcp || ipHeader->ip_p == ip_protocol_udp)
        {   /*Port unreachable (type 3, code 3) */
          sr_send_icmp(sr, (uint8_t *)ipHeader, ntohs(ipHeader->ip_len), 3, 3);
        }
        else
        {
          /* unknown protocol type, error*/
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
      printf("333333333333333333\n");
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

    int pos = 0;
    sr_ethernet_hdr_t *ethHeader = (sr_ethernet_hdr_t *)packet;
    sr_arp_hdr_t *arpHeader = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if * iface;
    iface = sr_get_interface(sr, interface);

    printf("Ethernet header is ");
    print_addr_eth(ethHeader);
    
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


int destinedForRouterInterface(struct  sr_instance* sr, uint32_t destIP) 
{
  /* TODO:// */
  /*
  struct sr_if* ip_interface = 0;
  ip_interface = sr->if_list;

  printf("Destination address: \d\n", destIP);

  printf("Starting looking for interface========\n");
  printf("Ip address: \d\n", ip_interface->ip);
  while(ip_interface->next) 
  {
    if(destIP == ip_interface->ip)
        return 1;
  
    ip_interface = ip_interface->next;
    printf("Ip address: \d\n", ip_interface->ip);
  }
  return 0;
  */
  /*
  printf("Destination address: \d\n", destIP);
  struct sr_if* if_walker = 0;
  printf("Starting looking for interface========\n");
  if_walker = sr->if_list;
  while(if_walker) {
    if(destIP == if_walker->ip)
        return 1;
    
    if_walker = if_walker->next;
  }
  */
  return 1;

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
  struct sr_rt* cur;
  struct sr_rt* lpm;
  unsigned long lpm_len;
  
  cur = sr->routing_table;
  lpm_len = 0;
  lpm = 0;
  
  /* Iterate through the interfaces and compare the masked addresses. If they are equal
   * then we found a match. We know it is longest if the netmask we used is greater
   * than the one used for the previous match. */
  while(cur != 0) {
    if (((cur->dest.s_addr & cur->mask.s_addr) == (addr.s_addr & cur->mask.s_addr)) &&
        (lpm_len <= cur->mask.s_addr)) {
        
      lpm_len = cur->mask.s_addr;
      lpm = cur;
    }
    
    cur = cur->next;
  }
  
  return lpm;
}


/*---------------------------------------------------------------------
 * Method: sr_encap_and_send_pkt(struct sr_instance* sr, 
 *                            uint8_t *packet, 
 *                            unsigned int len, 
 *                            uint32_t dip,
 *                            int send_icmp,
 *                            sr_ethertype type)
 * Scope:  Global
 *
 * Sends a packet of length len and destination ip address dip, by 
 * looking up the shortest prefix match of the dip (net byte order). 
 * If the destination is not found, it sends an ICMP host unreachable. 
 * If it finds a match, it then checks the arp cache to find the 
 * associated hardware address. If the hardware address is found it 
 * sends it, otherwise it queues the packet and sends an ARP request. 
 *
 *---------------------------------------------------------------------*/
void sr_encap_and_send_pkt(struct sr_instance* sr,
                        uint8_t *packet, 
                        unsigned int len, 
                        uint32_t dip,
                        int send_icmp,
                        enum sr_ethertype type)
{
  printf("============Ready to send packet===================\n");

  struct sr_rt *rt;
  struct sr_arpreq *arp_req;
  struct sr_ethernet_hdr eth_hdr;
  
  struct sr_arpentry *arp_entry;
  
  
  uint8_t *eth_pkt;
  struct sr_if *interface;
  
  unsigned int eth_pkt_len;
  
  /* Look up shortest prefix match in your routing table. */
  struct in_addr inad;
  inad.s_addr = dip;
  
  rt = sr_longest_prefix_match(sr, inad);
  
  /* If the entry doesn't exist, send ICMP host unreachable and return if necessary. */
  
  if (rt == 0) {
    printf("No NO===================\n");
    /*
    if (send_icmp)
      sr_send_icmp(sr, packet, len, ICMP_UNREACHABLE_TYPE, ICMP_NET_CODE);
    */
    return;
  }
  else
  {
    printf("YES YES===================\n");
  }
  /* Fetch the appropriate outgoing interface.  */

  interface = sr_get_interface(sr, rt->interface);
  printf("Run to here 1\n");
  /* If there is already an arp entry in the cache, send now. */  
  arp_entry = sr_arpcache_lookup(&sr->cache, rt->gw.s_addr);
  if (arp_entry || type == ethertype_arp) {
    printf("Run to here 2\n");
    print_hdr_ip(packet);
    /*printf("Start to Create the ethernet packet\n");*/
    /* Create the ethernet packet.*/
  
    eth_pkt_len = len + sizeof(eth_hdr);
    eth_hdr.ether_type = htons(type);
    
  /*   Destination is broadcast if it is an arp request. */
  
    if (type == ethertype_arp && ((struct sr_arp_hdr *)packet)->ar_op == htons(arp_op_request))
      memset(eth_hdr.ether_dhost, 255, ETHER_ADDR_LEN);
    
  /*   Destination is the arp entry mac if it is an ip packet or and are reply. */
  
    else
      memcpy(eth_hdr.ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);

    memcpy(eth_hdr.ether_shost, interface->addr, ETHER_ADDR_LEN);
    eth_pkt = malloc(eth_pkt_len);
    memcpy(eth_pkt, &eth_hdr, sizeof(eth_hdr));
    memcpy(eth_pkt + sizeof(eth_hdr), packet, len);
    sr_send_packet(sr, eth_pkt, eth_pkt_len, rt->interface);
    free(eth_pkt);
    if (arp_entry)
      free(arp_entry);
  
   /* Otherwise add it to the arp request queue. */
  
  } else {
    /*printf("add it to the arp request queue\n");*/
    printf("Run to here 3\n");
    print_hdr_ip(packet);
    eth_pkt = malloc(len);
    memcpy(eth_pkt, packet, len);
    arp_req = sr_arpcache_queuereq(&sr->cache, rt->gw.s_addr, eth_pkt, len, rt->interface);
    sr_arpreq_handle(sr, arp_req);
    free(eth_pkt);
  }
  
}


/*---------------------------------------------------------------------
 * Method: sr_send_icmp(struct sr_instance* sr, uint8_t *packet, unsigned int len, 
 *                      uint8_t type, uint8_t code)
 * Scope: Global
 *
 * This function sends an icmp of the supplied type and code, using the
 * supplied packet, which is an ip datagram. 
 *
 *---------------------------------------------------------------------*/
void sr_send_icmp(struct sr_instance* sr, uint8_t *packet, unsigned int len, uint8_t type, uint8_t code)
{
  printf("Now we know ICMP header, IP header, MAC ready to send back\n");
  printf("**************************************************\n");
  
  uint16_t icmp_len;
  uint32_t dst;
  /*struct sr_ip_hdr *error_ip_hdr;
  struct sr_icmp_hdr icmp_hdr;
  struct sr_icmp_hdr *icmp_hdr_ptr;
  struct sr_if *interface;
  struct sr_ip_hdr ip_hdr;
  struct sr_rt *rt;         */
  uint8_t *new_pkt;
  
  uint16_t total_len;

  sr_ip_hdr_t* IpHeader;
  sr_icmp_hdr_t* IcmpHeader;
  sr_icmp_hdr_t* IcmpHeaderCopy;

  IpHeader = (sr_ip_hdr_t *)packet;
  /*print_hdr_ip(IpHeader);*/
    
  /*Update the type of icmp from request to reply. */
  IcmpHeader =(sr_icmp_hdr_t*) ((uint8_t *)(IpHeader) + IpHeader->ip_hl * 4);
  /*print_hdr_icmp(IcmpHeader);*/
  
  /* Destination unreachable message or TTL exceeded. */
  
  if (type == 3 || type == 11)
  {
    /* Update icmp header fields. */
    IcmpHeader->icmp_type = type;
    IcmpHeader->icmp_code = code;
    IcmpHeader->icmp_sum = 0;
    
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
    /* Update the IP header fields. */

    IcmpHeader->icmp_sum = 0;
    IcmpHeader->icmp_code = code;
    IcmpHeader->icmp_type = type;
    print_hdr_icmp(IcmpHeader);
  
    dst = IpHeader->ip_src;
    IpHeader->ip_src = IpHeader->ip_dst;
    IpHeader->ip_dst = dst;


    /* Allocate a copy of this packet. */
  
    total_len = ntohs(IpHeader->ip_len);
    new_pkt = malloc(total_len);
    memcpy(new_pkt, IpHeader, total_len);
    icmp_len = total_len - 5;
    
  }
  
  IcmpHeaderCopy = (sr_icmp_hdr_t*) ((uint8_t *)(new_pkt) + IpHeader->ip_hl * 4);
  IcmpHeaderCopy->icmp_sum = cksum(IcmpHeaderCopy, icmp_len); 
  printf("**************************************************\n");
  printf("=======New ICMP header\n");
  print_hdr_icmp(IcmpHeaderCopy);
  printf("=======New IP header\n");
  print_hdr_ip(IpHeader);
  printf("**************************************************\n");
  printf("**************************************************\n");
  printf("**************************************************\n");
  
  /* Encapsulate and send */
  
  sr_encap_and_send_pkt(sr, new_pkt, total_len, dst, 0, ethertype_ip);
  free(new_pkt);
  
}

