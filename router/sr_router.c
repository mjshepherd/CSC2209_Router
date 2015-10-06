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

int destinedForRouterInterface(struct  sr_instance* sr, uint32_t destIP) {
  /* TODO:// */
  struct sr_if * current_if = sr->if_list;
  /*
  while(current_if!= 0)
    {
      current_if->ip = destIP
    }
    */
  return 1;
}

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
  /* Check ethertype of packet */
  uint16_t ethtype = ethertype(packet);
  if ( ethtype == ethertype_ip) {
    printf("Just recieved an ip packet! \n");
    
    unsigned int ethAddressHeaderLength = sizeof(sr_ethernet_hdr_t);
    sr_ip_hdr_t * ipHeader = (sr_ip_hdr_t *) (packet + ethAddressHeaderLength);
    print_hdr_ip(ipHeader);

    unsigned int checksum = ipHeader->ip_sum;
    ipHeader->ip_sum = 0;
    if(checksum != cksum(ipHeader, ipHeader->ip_hl*4))
    {
      printf("checksum %d: \n", checksum);
      printf("sum of ipheader %d: \n", cksum(ipHeader, ipHeader->ip_hl*4));
      printf("Bad ip checksum\n");
    }

    if(destinedForRouterInterface(sr, ipHeader->ip_dst))
    {
      if (ipHeader->ip_p == 1) {/* check if recieved ip packet contains an ICMP header */
        sr_icmp_hdr_t * icmpHeader = (sr_icmp_hdr_t *)(packet + ethAddressHeaderLength + sizeof(sr_ip_hdr_t));
        print_hdr_icmp(icmpHeader);
      }
    } else {

    }
    /* First check ip packet
      -checksum the ipheader
      -decrement TTL
      -check destination
      -if destination = one of our interfaces
        -if type = icmp echo request
            checksum the icmp header
            send echo reply back
        -if type == tcp or udp
          -send icmp port unreachable
        -else do nothing
      -else ????????
    */
 
    /* icmpHeader->icmp_sum = 0; */
    /*
    sr_ip_hdr_t* IpHeader =  (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    */


  } else if (ethtype == ethertype_arp) {
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

