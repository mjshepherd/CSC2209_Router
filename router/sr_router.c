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

#define ICMP_TYPE_REPLY 0
#define ICMP_TYPE_DEST_UNREACHABLE 3
#define ICMP_TYPE_REQUEST 8
#define ICMP_TYPE_TIME_EXCEED 11

#define ICMP_CODE_ZERO 0
#define ICMP_CODE_ONE 1
#define ICMP_CODE_THREE 3


void set_ethernet_header(sr_ethernet_hdr_t * ethHeader, uint8_t * destination_address, uint8_t * source_address);
struct sr_if * retrieveRouterInterface(struct  sr_instance* sr, uint32_t destIP);

int times = 0;


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
    
       
        /* Validate checksum. */
    
        received_cksum = ipHeader->ip_sum;
        ipHeader->ip_sum = 0;
        expected_cksum = cksum(ipHeader, ipHeader->ip_hl*4);
       

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
                if (icmpHeader->icmp_type == ICMP_TYPE_REQUEST) 
                {
                    /* Send icmp echo reply. */
				
					printf("==========================OKOKOKOK==========================\n");
					printf("==================================================================\n");
					printf("=================== Here ready to send reply to port==============\n");
					sr_ip_hdr_t temp_add;
					temp_add.ip_src = ipHeader->ip_dst;
					ipHeader->ip_dst = ipHeader->ip_src;
					ipHeader->ip_src = temp_add.ip_src;

					icmpHeader->icmp_sum = 0;
					icmpHeader->icmp_code = ICMP_CODE_ZERO;
					icmpHeader->icmp_type = ICMP_TYPE_REPLY;
					icmpHeader->icmp_sum = cksum(icmpHeader, ntohs(ipHeader->ip_len) - ipHeader->ip_hl*4);

					print_hdr_ip((uint8_t *)ipHeader);
					
                    sr_send_icmp(sr, (uint8_t *)ipHeader, ntohs(ipHeader->ip_len), ICMP_TYPE_REPLY, ICMP_CODE_ZERO);
                    return;
                }
            }/* End for Ip packet is an ICMP packet.*/
            else if (ipHeader->ip_p == ip_protocol_tcp || ipHeader->ip_p == ip_protocol_udp)
            {   /*Port unreachable (type 3, code 3) */
                sr_send_icmp(sr, (uint8_t *)ipHeader, ntohs(ipHeader->ip_len), ICMP_TYPE_DEST_UNREACHABLE, ICMP_CODE_THREE);
            }
            else
            {
                /* unknown protocol type, error*/
                printf("Unknown IP protocol type, dropping packet.\n");
                return;
            }
        }    /* end for Ip packet destination is for router interface */
        else 
        {  
            uint8_t *forward_ip_packet;
            unsigned int len;

            /* Update the ip header ttl. */
            ipHeader->ip_ttl--;
    
            /* If the ttl is equal to 0, send an ICMP Time exceeded response and return. */
            len = ntohs(ipHeader->ip_len);;
            if (ipHeader->ip_ttl == 0) 
            {
                sr_send_icmp(sr, (uint8_t *)ipHeader, len, ICMP_TYPE_TIME_EXCEED, ICMP_CODE_ZERO);
                return;
            }
    
            /* Update the checksum. */
            ipHeader->ip_sum = 0;
            ipHeader->ip_sum = cksum(ipHeader, ipHeader->ip_hl*4);

			sr_icmp_hdr_t * icmpHeader = (sr_icmp_hdr_t *)(packet + ethAddressHeaderLength + sizeof(sr_ip_hdr_t));

			
            /* Make a copy, encapsulate and send it on. */
            
            forward_ip_packet = malloc(len);
            memcpy(forward_ip_packet, ipHeader, len);

			printf("======= Before eneter the function sr_send_ehternet_packet ip header info ============\n");
			print_hdr_ip(forward_ip_packet);

			
            sr_send_ehternet_packet(sr, forward_ip_packet, len, ipHeader->ip_dst, 0, ethertype_ip);
            free(forward_ip_packet);
			
        }
		
    }  /* end for IP packet*/ 
    else if (ethtype == ethertype_arp) 
    {

        printf("==============================================\n");
        printf("==============================================\n");
        printf("==============================================\n");
        printf("Recieved an ARP packet! \n");
        print_hdrs(packet, len);
        
        int pos = 0;
		struct sr_arpreq *arp_req;

        sr_ethernet_hdr_t *ethHeader = (sr_ethernet_hdr_t *)packet;
        sr_arp_hdr_t *arpHeader = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
		

        struct sr_if * iface;
        iface = sr_get_interface(sr, interface);
		struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, arpHeader->ar_sip);

		if(arp_entry != 0)
		{
			printf("We already have this sender MAC address and IP in the cache database\n "); 
		}
		else
		{
			printf("We need to add the sender MAC address and IP address. \n");
			arp_req = sr_arpcache_insert(&sr->cache, arpHeader->ar_sha, arpHeader->ar_sip);
			/* There are packets waiting on this arp request. Send them. */
			if (arp_req != 0) 
			{
				printf("There is packet waiting on this arp request. \n");
			}
			else
			{
				printf("No packet waiting on this arp request. \n");
			}
		}

		/* Handle a request. */
		if (ntohs(arpHeader->ar_op) == arp_op_request) 
		{
			printf("Ready to send reply back. \n");
			/*process_arp_request(sr, arpHeader, rec_interface, ethHeader, packet,len);*/

			int pos = 0;
			arpHeader->ar_op = ntohs(2);
			for (pos = 0; pos < ETHER_ADDR_LEN; pos++) {
			  arpHeader->ar_tha[pos] = arpHeader->ar_sha[pos];
			}
			arpHeader->ar_tip = arpHeader->ar_sip;
			for (pos = 0; pos < ETHER_ADDR_LEN; pos++) {
			  arpHeader->ar_sha[pos] = iface->addr[pos];
			}
			arpHeader->ar_sip = iface->ip;

			 
			for (pos = 0; pos < ETHER_ADDR_LEN; pos++) {
				ethHeader->ether_dhost[pos] = ethHeader->ether_shost[pos];
			}

			for (pos = 0; pos < ETHER_ADDR_LEN; pos++) {
				ethHeader->ether_shost[pos] = iface->addr[pos];
			}

			sr_send_packet(sr, packet, len, interface);
		}
		else if (ntohs(arpHeader->ar_op) == arp_op_reply) 
		{
			/*//////////////////////////////////////////////////////////////////////////*/
			/*//////////////////////////////////////////////////////////////////////////*/
			printf("Receive a ARP reply, need to send IP packet. \n");
			struct sr_packet *cur;
			struct sr_ip_hdr *ip_hdr;
			
			cur = arp_req->packets;
			print_hdr_ip((uint8_t *)cur->buf);
			
			while (cur != 0) 
			{
				ip_hdr = (struct sr_ip_hdr *)cur->buf;
				sr_send_ehternet_packet(sr,  cur->buf,  cur->len,  ip_hdr->ip_dst, 0,  ethertype_ip);
				cur = cur->next;
			}
			
		}

        
    
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


struct sr_rt *sr_longest_prefix_match(struct sr_instance* sr, struct in_addr addr)
{
     
    printf("Trying to find suitable ip address: \n");
    print_addr_ip(addr);

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


void sr_send_ehternet_packet(struct sr_instance* sr,
                            uint8_t *packet,
                            unsigned int len,
                            uint32_t destination_ip,
                            int icmp_error_type,
                            enum sr_ethertype eth_type)
{
    
	times = times + 1;
	printf("============Ready to send packet times %d ===================\n", times);
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
        printf("============== No Route for this IP================\n");
		printf("============== We need send ICMP type 3, code 0 ================\n");
		
		sr_send_icmp(sr, packet, len, ICMP_TYPE_DEST_UNREACHABLE, ICMP_CODE_ZERO);
        return;
    }
	else
	{
		printf("We found the IP route in the route table. \n");
	}

    /* Fetch the appropriate outgoing interface.  */
    outgoing_interface = sr_get_interface(sr, rt->interface);

    /* If there is already an arp entry in the cache, send now. */  
    arp_entry = sr_arpcache_lookup(&sr->cache, rt->gw.s_addr);
    if (arp_entry || eth_type == ethertype_arp) {
        printf("Destination was found in the arpcache. \n");
		printf("============================================== \n");
		printf("============================================== \n");


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
        
		
		if( icmp_error_type > 0 )
		{

			printf("============= print ip header after create etherenet header===================\n");
			print_hdr_ip(packet);


			/*

			printf("============= In the new packet, icmp header ===================\n");
			sr_ip_hdr_t * ipHeaderTemp = (sr_ip_hdr_t *) (eth_pkt + sizeof(sr_ethernet_hdr_t));
			sr_icmp_hdr_t * icmpHeader = (sr_icmp_hdr_t *)(eth_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

			
			
			icmpHeader->icmp_sum = 0;/*cksum(icmpHeader, ntohs(ipHeaderTemp->ip_len) - ipHeaderTemp->ip_hl*4);
			print_hdr_icmp((uint8_t*)icmpHeader);
			printf("============= In the new packet, End ===================\n");
			*/
		}
		

		printf("Following is the ethernet info:\n");
        print_hdrs(eth_pkt, eth_pkt_len);

        printf("Trying to send the above ethernet packet on the interface with ip: %s\n", outgoing_interface->name);

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
		printf("Here we want to add this ipPacket to the arp queue.\n");
		print_hdr_ip(ip_pkt);
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
    printf("Now we know ICMP header, IP header, MAC ready to send back\n");
    printf("**************************************************\n");


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
	printf("============== Now we enter type 3 icmp function\n");
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
	ip_hdr.ip_src = ipHeader->ip_dst;  
	ip_hdr.ip_len = htons( 20 + sizeof(icmp3Header));

	ip_hdr.ip_sum = cksum(&ip_hdr, 20);

	printf("============== new ip header info\n");
	print_hdr_ip((uint8_t*)&ip_hdr);
	
       
		
	total_len = 20 + sizeof(icmp3Header);
	printf("========total length of new ip packet is %d\n", total_len);
		
	new_pkt = malloc(total_len);
	memcpy(new_pkt, &ip_hdr, 20);           /*copy the first 20 bytes ip header info to the new packet*/

	memcpy(new_pkt + 20, &icmp3Header, sizeof(icmp3Header));

	/*
	printf("========Before we send out the packet, check ip header again\n");
	print_hdr_ip((uint8_t*)new_pkt);
	*/
    
	sr_send_ehternet_packet(sr, new_pkt, total_len, ip_hdr.ip_dst, 1, ethertype_ip);
	return;
	printf("this is a change");
    
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
    sr_send_ehternet_packet(sr, new_pkt, len, ipHeader->ip_dst, 0, ethertype_ip);
    
}
