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
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

sr_arp_hdr_t *create_arp_req_hdr(struct sr_instance* sr, struct sr_arpreq *req, struct sr_if* sr_if);
sr_arp_hdr_t *create_arp_rep_hdr(sr_arp_hdr_t *arp_req, struct sr_if *sr_if);


struct sr_rt * sr_find_longest_prefix_match_interface(struct sr_rt *rt, uint32_t dest);
uint32_t sr_longest_prefix_match(uint32_t rt_dest, uint32_t mask, uint32_t dest);

int ip_destination_to_us(struct sr_instance *sr, sr_ip_hdr_t *ip_hdr) 
{
	struct sr_if *if_walker = sr->if_list;
	while(if_walker) 
	{
		if (if_walker->ip == ip_hdr->ip_dst) 
		{
			return 1;
		}
		if_walker = if_walker->next;
	}
	return 0;
}


int destined_for_us(struct sr_instance *sr, struct sr_nat *nat, uint8_t* packet, unsigned int len, char *interface) 
{
  
	sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet, len);

	if (sr->nat_enabled && !strcmp(interface, EXTER_IF)) 
	{
		if (ip_hdr->ip_p == ip_protocol_icmp) 
		{
			uint16_t data_size = ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t) - sizeof(sr_icmp_hdr_t);

			sr_icmp_hdr_t *icmp_hdr = get_icmp_hdr(packet, len, data_size);
			uint16_t aux_ext = icmp_hdr->icmp_id;

			if (sr_nat_lookup_external(nat, aux_ext, nat_mapping_icmp)) 
			{
				return 0;
			}
		} 
		else if (ip_hdr->ip_p == ip_protocol_tcp) 
		{
			uint16_t data_size = ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t) - sizeof(sr_tcp_hdr_t);

			sr_tcp_hdr_t *tcp_hdr = get_tcp_hdr(packet, len, data_size);
			uint16_t aux_ext = tcp_hdr->tcp_dest_port;

			if (sr_nat_lookup_external(nat, aux_ext, nat_mapping_tcp)) 
			{
				return 0;
			}
		}
  }

  return ip_destination_to_us(sr, ip_hdr);
}

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache/nat and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    if (sr->nat_enabled) {
      if (sr_nat_init(&(sr->nat))) {
        fprintf(stderr, "Fail to initialize NAT.\n");
        exit(1);
      }
    }

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

void sr_handlepacket(struct sr_instance* sr, uint8_t * packet/* lent */,unsigned int len, char* interface/* lent */) 
{
	  /* REQUIRES */
	  assert(sr);
	  assert(packet);
	  assert(interface);
	  /*assert(sr_get_interface(sr, interface));*/

	  if (len < sizeof(sr_ethernet_hdr_t)) 
	  {
			fprintf(stderr, "Failed to handle the packet due to insufficient length, drop it\n");
			return;
	  };
	  
	  /*NOTE:This is an attempt to fix the port unreachable problem*/
	  if (0 == sr_get_interface(sr, interface)){ /*send port unreachable*/
		printf ("Testing, GOT HERE!");
		/*sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));*/
		sr_ethernet_hdr_t *ether_hdr =  (sr_ethernet_hdr_t *) packet;
		uint32_t destination = ntohl(ether_hdr->ether_shost);
		uint32_t source = ntohl(ether_hdr->ether_dhost);
		uint8_t *icmp_packet = create_icmp_packet(sr, 3, 3, 0, 0, destination, ICMP_DATA_SIZE, NULL, &len,source);
						
		if (icmp_packet) 
		{
			send_packet(sr, icmp_packet, len,NULL );
		}
		else
		{
			fprintf(stderr, "Failed to create an ICMP Port-Unreachable packet\n");
		}

		return;
	  }
	  struct sr_if *sr_if = sr_get_interface(sr, interface);

	  fprintf(stderr, "----------------------------------------\n");
 	  fprintf(stderr, "Received following packet\n");
	  print_hdrs(packet, len);

	  uint16_t ethtype = ethertype(packet);

	  if (ethtype == ethertype_ip) 
	  {
			/* IP */
			sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet, len);
			if (!ip_hdr) 
			{
				return;
	        }

			uint8_t *ip_data = (uint8_t *) malloc(ICMP_DATA_SIZE);
			memcpy_byte_by_byte(ip_data, ip_hdr, ICMP_DATA_SIZE);
			uint32_t ip_intended_dst_icmp = ntohl(ip_hdr->ip_dst);
			uint32_t ip_dst_icmp = ntohl(ip_hdr->ip_src);
			
			if (destined_for_us(sr, &(sr->nat), packet, len, interface))    /* Packet for us */
			{
      
				 fprintf(stderr, "*** -> Recevied IP packet for us.\n");

				 uint8_t ip_proto = ip_hdr->ip_p;

				 if (ip_proto == ip_protocol_icmp) 
				 {
						/* ICMP for us */
						uint16_t data_size = ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t) - sizeof(sr_icmp_hdr_t);

						fprintf(stderr, "*** -> Recevied ICMP packet for us.\n");
						sr_icmp_hdr_t *icmp_hdr = get_icmp_hdr(packet, len, data_size);

						if (!icmp_hdr) 
						{
							free(ip_data);
							return;
						}

						if (icmp_hdr->icmp_type == echo_request) 
						{
          
							fprintf(stderr, "*** -> Recevied ICMP echo request for us.\n");

							uint8_t *data = (uint8_t *) malloc(data_size);
							memcpy_byte_by_byte(data, (uint8_t *) icmp_hdr + sizeof(sr_icmp_hdr_t), data_size);

							uint8_t *icmp_data = (uint8_t *) malloc(ICMP_DATA_SIZE);
							memcpy_byte_by_byte(icmp_data, ip_hdr, ICMP_DATA_SIZE);

							unsigned int length = 0;
							uint8_t *icmp_packet = create_icmp_packet(sr, 0, 0, icmp_hdr->icmp_id, icmp_hdr->icmp_seq, ip_dst_icmp, data_size, data, &length,0);
			  
							if (icmp_packet) 
							{
								send_packet(sr, icmp_packet, length, icmp_data);
							}

							free(data);
							free(ip_data);
							free(icmp_data);
							
							return;
						} 
						else 
						{
							fprintf(stderr, "Failed to handle the ICMP packet due to type unrecognized, drop it\n");
							free(ip_data);
							return;
						}
				 
				 }    /* end for icmp packet handle*/
				 else if (ip_proto == ip_protocol_tcp || ip_proto == ip_protocol_udp) 
				 {
						/* TCP or UDP for us */
						fprintf(stderr, "*** -> Recevied TCP/UDP for us.\n");

						if (!strcmp(interface, EXTER_IF)) 
						{
							goto forward;
						}

						unsigned int length = 0;
						uint8_t *icmp_packet = create_icmp_packet(sr, 3, 3, 0, 0, ip_dst_icmp, ICMP_DATA_SIZE, ip_data, &length,ip_intended_dst_icmp);
						
						if (icmp_packet) 
						{
							send_packet(sr, icmp_packet, length, ip_data);
						}

						free(ip_data);
						return;
				} 
				else 
				{
						/* Other ip protocol type for us */
						fprintf(stderr, "Unrecognized Ip Type: %d\n", ip_proto);
						free(ip_data);
						return;
				}
			} 
			else 
			{
      /* Packet not for us */
      forward:
        fprintf(stderr, "*** -> Recevied IP packet not for us.\n");

      struct sr_rt *best_rt_entry = sr_find_longest_prefix_match_interface(sr->routing_table, ntohl(ip_hdr->ip_dst));
      if (!best_rt_entry && !strcmp(interface, INTER_IF))
	  {
        /* Fail to match in routing table */
        fprintf(stderr, "Failed to handle the IP packet due to routing table no match, drop it\n");

        /* Send ICMP destination net unreachable back to sender */
        uint32_t ip_dst_icmp = ntohl(ip_hdr->ip_src);
        unsigned int length = 0;

        void *data = malloc(ICMP_DATA_SIZE);
        memcpy_byte_by_byte(data, ip_hdr, ICMP_DATA_SIZE);

        uint8_t *icmp_packet = create_icmp_packet(sr, 3, 0, 0, 0, ip_dst_icmp, ICMP_DATA_SIZE, data, &length, 0);
        if (icmp_packet) {
          send_packet(sr, icmp_packet, length, data);
        }
        return;
      }

      int nat_result = 0;
      if (sr->nat_enabled && nat_support(packet, len)) 
	  {
			nat_result = nat_handlepacket(sr, packet, len, interface);
			if (nat_result == -1) 
			{
				fprintf(stderr, "NAT failed to translate packet, drop it.\n");
				return;
			}
			printf("============NAT handle packet\n");

			fprintf(stderr, "Following packet after NAT rewrite.\n");
			print_hdrs(packet, len);
      }

      if (nat_result == 2) {
        return;
      }

      best_rt_entry = sr_find_longest_prefix_match_interface(sr->routing_table, ntohl(ip_hdr->ip_dst));
      if (nat_support(packet, len) && nat_result && best_rt_entry && strcmp(best_rt_entry->interface, interface)) {
        fprintf(stderr, "NAT failed to translate packet, drop it.\n");
        return;
      }


      /* Decrement and check TTL */
      uint8_t new_ip_ttl = ip_hdr->ip_ttl - 1;
      if (new_ip_ttl == 0) {
        fprintf(stderr, "*** -> Failed to forward the IP packet due to TTL reaching zero, drop it\n");

        unsigned int length = 0;
        uint8_t *icmp_packet = create_icmp_packet(sr, 11, 0, 0, 0, ip_dst_icmp, ICMP_DATA_SIZE, ip_data, &length,0);
        if (icmp_packet) {
        send_packet(sr, icmp_packet, length, ip_data);
        }

        free(ip_data);
        return;
      }
      ip_hdr->ip_ttl = new_ip_ttl;

      /* Recalculate checksum */
      memset(&(ip_hdr->ip_sum), 0, sizeof(uint16_t));
      uint16_t new_ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
      ip_hdr->ip_sum = new_ip_sum;

      send_packet(sr, packet, len, ip_data);

      free(ip_data);
      return;
    }
  } else if (ethtype == ethertype_arp) {
    /* ARP */
    fprintf(stderr, "*** -> Recevied ARP packet.\n");
    sr_arp_hdr_t *arp_hdr = verify_arp_hdr(packet, len);
    if (!arp_hdr) {
      return;
    }
    unsigned short ar_op = ntohs(arp_hdr->ar_op);

    if (ar_op == arp_op_request) {
      /* Handle ARP request */
      fprintf(stderr, "*** -> Recevied ARP request.\n");
      sr_arp_hdr_t *arp_rep = create_arp_rep_hdr(arp_hdr, sr_if);
      uint8_t *arp_packet = create_ethernet_hdr((uint8_t *) arp_rep, arp_rep->ar_tha, arp_rep->ar_sha, sizeof(sr_arp_hdr_t), ethertype_arp);

      sr_send_packet(sr, arp_packet, sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t), interface);
    } else if (ar_op == arp_op_reply) {
      /* Handle ARP reply */

      struct sr_arpreq *arpreq = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
      if (arpreq) {
        /* Send packets that are wating for this ARP reply */
        fprintf(stderr, "*** -> Recevied ARP reply.\n");
        struct sr_packet* packet_walker = arpreq->packets;

        while (packet_walker) {
          uint8_t *buf = packet_walker->buf;
          unsigned int length = packet_walker->len;

          if (length < sizeof(sr_ethernet_hdr_t)) {
            fprintf(stderr, "Failed to handle the packet due to insufficient length, drop it\n");
            return;
          };

          sr_ethernet_hdr_t *ethernet_packet = (sr_ethernet_hdr_t *) buf;
          int i;
          for (i = 0; i < ETHER_ADDR_LEN; i++) {
            ethernet_packet->ether_dhost[i] = arp_hdr->ar_sha[i];
          }

          sr_send_packet(sr, buf, length, packet_walker->iface);

          packet_walker = packet_walker->next;
        }
      }
      sr_arpreq_destroy(&(sr->cache), arpreq);
    } else {
      fprintf(stderr, "Unrecognized ARP Type: %d\n", ar_op);
      return;
    }
  } else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
    return;
  }
  fprintf(stderr, "----------------------------------------\n");

}/* end sr_ForwardPacket */

void send_packet(struct sr_instance* sr, uint8_t *packet, unsigned int len, void *icmp_data) 
{
  
	if (packet == NULL) 
	{
		return;
	}
  
	sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *) packet;
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

	/* Check routing table */
	struct sr_rt *best_rt_entry = sr_find_longest_prefix_match_interface(sr->routing_table, ntohl(ip_hdr->ip_dst));
	if (!best_rt_entry) 
	{
		/* Fail to match in routing table */
		fprintf(stderr, "Failed to handle the IP packet due to routing table no match, drop it\n");

		/* Send ICMP destination net unreachable back to sender */
		uint32_t ip_dst_icmp = ntohl(ip_hdr->ip_src);
		unsigned int length = 0;

		void *data = malloc(ICMP_DATA_SIZE);
		memcpy_byte_by_byte(data, ip_hdr, ICMP_DATA_SIZE);

		uint8_t *icmp_packet = create_icmp_packet(sr, 3, 0, 0, 0, ip_dst_icmp, ICMP_DATA_SIZE, data, &length,0);
    
		if (icmp_packet) 
		{
			send_packet(sr, icmp_packet, length, data);
		}
		return;
	}
  
	/* Check ARP cache if the gateway ip exists */
	uint32_t gateway_net = best_rt_entry->gw.s_addr;
	struct sr_if *outgoing_if = sr_get_interface(sr, best_rt_entry->interface);
  
	if (!outgoing_if) 
	{
		fprintf(stderr, "Couln't find interface according to routing table\n");
		return;
	}
  
	int i;
	for (i = 0; i < ETHER_ADDR_LEN; i++) 
	{
		ethernet_hdr->ether_shost[i] = outgoing_if->addr[i];
	}

	struct sr_arpentry *arpentry = sr_arpcache_lookup(&(sr->cache), gateway_net);
	if (!arpentry) 
	{
		/* Didn't find the ip the ARP cache, send an ARP request */
		struct sr_arpreq *sr_arpreq = sr_arpcache_queuereq(&(sr->cache), gateway_net, packet, len, best_rt_entry->interface);
		handle_arpreq(sr, sr_arpreq);
		return;
	}
  
	/* ARP cache found, go ahead forwarding it */
	for (i = 0; i < ETHER_ADDR_LEN; i++) 
	{
		ethernet_hdr->ether_dhost[i] = arpentry->mac[i];
	}

	sr_send_packet(sr, packet, len, best_rt_entry->interface);
	free(arpentry);
}


sr_arp_hdr_t *create_arp_rep_hdr(sr_arp_hdr_t *arp_req, struct sr_if *sr_if) 
{
	  /* Requires */
	  assert(arp_req);
	  assert(sr_if);

	  sr_arp_hdr_t *arp_rep = (sr_arp_hdr_t *) malloc(sizeof(sr_arp_hdr_t));

	  if (!arp_rep) 
	  {
			perror("malloc failed");
			return 0;
	  }

	  arp_rep->ar_hrd = arp_req->ar_hrd;
	  arp_rep->ar_pro = arp_req->ar_pro;
	  arp_rep->ar_hln = arp_req->ar_hln;
	  arp_rep->ar_pln = arp_req->ar_pln;
	  arp_rep->ar_op = htons(arp_op_reply);

	  int i;
	  for (i = 0; i < ETHER_ADDR_LEN; i++) 
	  {
			arp_rep->ar_sha[i] = sr_if->addr[i];
			arp_rep->ar_tha[i] = arp_req->ar_sha[i];
	  }
	  arp_rep->ar_sip = sr_if->ip;
	  arp_rep->ar_tip = arp_req->ar_sip;

	  return arp_rep;
}

sr_arp_hdr_t *create_arp_req_hdr(struct sr_instance* sr, struct sr_arpreq *req, struct sr_if* sr_if) 
{
	
		sr_arp_hdr_t *arp_req = (sr_arp_hdr_t *) malloc(sizeof(sr_arp_hdr_t));

		if (!arp_req) 
		{
			perror("malloc failed");
			return 0;
		}

		arp_req->ar_hrd = htons(0x0001);
		arp_req->ar_pro = htons(ethertype_ip);
		arp_req->ar_hln = 0x0006;
		arp_req->ar_pln = 0x0004;
		arp_req->ar_op = htons(arp_op_request);
		arp_req->ar_sip = sr_if->ip;
		int i;
		for (i = 0; i < ETHER_ADDR_LEN; i++) 
		{
			arp_req->ar_sha[i] = sr_if->addr[i];
			arp_req->ar_tha[i] = 0xFF;
		}
		arp_req->ar_tip = req->ip;

		return arp_req;
}



struct sr_rt*  sr_find_longest_prefix_match_interface(struct sr_rt *rt, uint32_t dest) 
{
     /* -- REQUIRES -- */
	 struct sr_rt *rt_walker = rt;
	 int longest = 0;
	 struct sr_rt *longest_sr_rt = 0;

	 while (rt_walker) 
	 {
			uint32_t lpm = sr_longest_prefix_match(rt_walker->dest.s_addr, rt_walker->mask.s_addr, dest);
			if (lpm > longest) 
			{
				longest = lpm;
				longest_sr_rt = rt_walker;
			}
			rt_walker = rt_walker->next;
	}

	
	if (longest_sr_rt) 
	{
		return longest_sr_rt;
	}

	return 0;
}



uint8_t *create_icmp_packet(struct sr_instance* sr, uint8_t icmp_type, uint8_t icmp_code, uint16_t icmp_id, uint16_t icmp_seq, uint32_t ip_dst, uint16_t data_size, void *data, unsigned int *length, uint32_t icmp33_src) 
{
  
	uint8_t *icmp_packet;

	if (icmp_type == 3 || icmp_type == 11) 
	{
		icmp_packet = create_icmp_t3_hdr(icmp_type, icmp_code, data);
	} 
	else 
	{
		icmp_packet = create_icmp_hdr(icmp_type, icmp_code, icmp_id, icmp_seq, data_size, data);
	}
  
	if (!icmp_packet) 
	{
		fprintf(stderr, "Fail creating ICMP packet\n");
		return NULL;
	}

	uint32_t ip_src = 0;
	if (icmp_type == 3 && icmp_code == 3){
		ip_src = icmp33_src;
	}else{
		struct sr_rt *best_rt = sr_find_longest_prefix_match_interface(sr->routing_table, ip_dst);
	
		if (best_rt) 
		{
			struct sr_if *outgoing_if = sr_get_interface(sr, best_rt->interface);
			if (outgoing_if) 
			{
				ip_src = htonl(outgoing_if->ip);
			}
		}
	}
	uint8_t *ip_packet = create_ip_hdr(icmp_type == 3 || icmp_type == 11, icmp_packet, ip_src, ip_dst, data_size);
	if (!ip_packet) 
	{
		fprintf(stderr, "Fail creating IP packet\n");
		return NULL;
	}
	
	int len = ntohs(((sr_ip_hdr_t *) ip_packet)->ip_len);

	uint8_t *ethernet_packet = create_ethernet_hdr(ip_packet, NULL, NULL, len, ethertype_ip);
	if (!ethernet_packet) 
	{
		fprintf(stderr, "Fail creating ethernet packet\n");
		return NULL;
	}

	*length = len + sizeof(sr_ethernet_hdr_t);

	return ethernet_packet;
}

uint32_t sr_longest_prefix_match(uint32_t rt_dest, uint32_t mask, uint32_t dest) 
{
	int j = 31;
	while (j > -1 && ((mask >> j) & 1)) 
	{
		j--;
	}
	
	int mask_number = 31 - j;
	int i = mask_number;
	while (i) 
	{
		int rt_dest_bit = (ntohl(rt_dest) >> i) & 1;
		int dest_bit = (dest >> i) & 1;

		if (rt_dest_bit != dest_bit) 
		{
			return 0;
		}
		i--;
	}
	return mask_number;
}