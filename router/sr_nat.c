#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "sr_router.h"
#include "sr_nat.h"
#include "sr_protocol.h"
#include "sr_utils.h"


struct sr_nat_mapping* create_nat_mapping(sr_nat_mapping_type type, sr_nat_mapping_direction_type direction_type, uint32_t ip_int, uint32_t ip_ext, uint16_t aux_int, uint8_t *icmp_data);


uint16_t get_external_port(uint32_t ip_int, uint16_t aux_int) 
{
	uint16_t result = (ip_int + aux_int) % MAX_PORT_NUM;

	if (result < 1024) 
	{
		result += 1024;
	}

	return result;
}

/*
static const char *sr_nat_tcp_state_string[] = {
    "ESTAB",
    "TRANS"
};
*/

sr_nat_tcp_state calculate_tcp_state(int syn, int ack, int fin, int rst) 
{
	if (fin || syn || rst) 
	{
		return TRANS;
	} 
	else if (ack) 
	{
		return ESTAB;
	}
	return TRANS;
}


struct sr_nat_connection* create_tcp_connection(int32_t ip_ext, uint16_t aux_ext, uint32_t ip_remote, uint16_t aux_remote) 
{
  
	struct sr_nat_connection *conn = (struct sr_nat_connection *) malloc(sizeof(struct sr_nat_connection));

	conn->ip_ext = ip_ext;
	conn->aux_ext = aux_ext;
	conn->ip_remote = ip_remote;
	conn->aux_remote = aux_remote;
	conn->state = TRANS;

	return conn;
}


void update_tcp_conection(struct sr_nat *nat, uint32_t ip_ext, uint16_t aux_ext, uint32_t ip_remote, uint16_t aux_remote, int syn, int ack, int fin, int rst) 
{
	/* Requires */
	assert(nat);

	pthread_mutex_lock(&(nat->lock));

	struct sr_nat_mapping *mapping_walker = nat->mappings;
  while (mapping_walker) 
  {
		if (mapping_walker->type == nat_mapping_tcp && mapping_walker->aux_ext == aux_ext) 
		{
			break;
		}
		mapping_walker = mapping_walker->next;
  }

  assert(mapping_walker);

  struct sr_nat_connection *con_walker = mapping_walker->conns;
  /*
  fprintf(stderr, "Looking for conection with ip_ext =  %d, aux_ext = %d, ip_remote = %d, aux_remote = %d\n", 
    ntohl(ip_ext), ntohs(aux_ext), ntohl(ip_remote), ntohs(aux_remote));
	*/

  while (con_walker) 
  {
		if (con_walker->ip_ext == ip_ext &&
			con_walker->aux_ext == aux_ext &&
			con_walker->ip_remote == ip_remote &&
			con_walker->aux_remote == aux_remote) 
		{
			break;
		}
		con_walker = con_walker->next;
  }

  if (!con_walker) 
  {
		con_walker = create_tcp_connection(ip_ext, aux_ext, ip_remote, aux_remote);
		con_walker->next = mapping_walker->conns;
		mapping_walker->conns = con_walker;
  }

  con_walker->state = calculate_tcp_state(syn, ack, fin, rst);


  con_walker->last_updated = time(NULL);

  pthread_mutex_unlock(&(nat->lock));
}


int sr_nat_init(struct sr_nat *nat) 
{ 
	/* Initializes the nat */

	assert(nat);

	/* Acquire mutex lock */
	pthread_mutexattr_init(&(nat->attr));
	pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
	int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

	/* Initialize timeout thread */

	pthread_attr_init(&(nat->thread_attr));
	pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
	pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
	pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

	/* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

	nat->mappings = NULL;
	/* Initialize any variables here */

	return success;
}


int sr_nat_destroy(struct sr_nat *nat)
{  
	/* Destroys the nat (free memory) */

	pthread_mutex_lock(&(nat->lock));

	/* free nat memory here */

	pthread_kill(nat->thread, SIGKILL);
	return pthread_mutex_destroy(&(nat->lock)) && pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) 
{  
	/* Periodic Timout handling */
	struct sr_nat *nat = (struct sr_nat *) nat_ptr;

	unsigned int icmp_timeout = nat->icmp_timeout;
	unsigned int tcp_establish_timeout = nat->tcp_establish_timeout;
	unsigned int tcp_trans_timeout = nat->tcp_trans_timeout;

	while (1) 
	{
		sleep(1.0);
		pthread_mutex_lock(&(nat->lock));

		time_t curtime = time(NULL);

	    /* handle periodic tasks here */
		struct sr_nat_mapping *mapping_walker = nat->mappings;
		struct sr_nat_mapping *pre_mapping = NULL;

		while (mapping_walker) 
		{
			if (mapping_walker->type == nat_mapping_tcp) 
			{
				struct sr_nat_connection *con_walker = mapping_walker->conns;
				struct sr_nat_connection *pre_con = NULL;

				if (mapping_walker->direction_type == EXTER_MAP) 
				{
					if (difftime(curtime, mapping_walker->last_updated) > 6.0) 
					{
						uint16_t aux_ext = mapping_walker->aux_int;
						uint32_t ip_remote = mapping_walker->ip_ext;
						/*NOTE:ip_src here is something of a filler, 
						 * we need to get the original destination address of the incoming packet here instead*/
						uint32_t ip_src = mapping_walker->ip_int;
						struct sr_nat_mapping *walker = nat->mappings;
						while (walker) 
						{
							if (walker->direction_type == INTER_MAP && walker->type == nat_mapping_tcp && walker->aux_ext == aux_ext) 
							{
								break;
							}
							walker = walker->next;
						}

						if (!walker) 
						{
							struct sr_instance *sr = nat->sr;
							unsigned int length = 0;
							uint8_t *icmp_3_3 = create_icmp_packet(sr, 3, 3, 0, 0, ntohl(ip_remote), ICMP_DATA_SIZE, mapping_walker->icmp_data, &length,ntohl(ip_src));
							send_packet(sr, icmp_3_3, length, mapping_walker->icmp_data);

							free(mapping_walker->icmp_data);
						}

						if (pre_mapping) 
						{
							pre_mapping->next = mapping_walker->next;
						} 
						else 
						{
							nat->mappings = mapping_walker->next;
						}

						mapping_walker = mapping_walker->next;
						continue;
					}      /* here, if MUST NOT respond to an unsolicited inbound SYN packet for at least 6 seconds */
				} 
				else if (!con_walker) 
				{
					/* No connection exists for this mapping, clean it up */
					if (pre_mapping) 
					{
						pre_mapping->next = mapping_walker->next;
					} 
					else 
					{
						nat->mappings = mapping_walker->next;
					}

					mapping_walker = mapping_walker->next;
					free(mapping_walker);
					continue;
				}

				while (con_walker) 
				{
					if ((con_walker->state == ESTAB && difftime(curtime, con_walker->last_updated) > tcp_establish_timeout) || 
						(con_walker->state != ESTAB && difftime(curtime, con_walker->last_updated) > tcp_trans_timeout)) 
					{
						/* This connection has timed out, clean it up */
						if (pre_con) 
						{
							pre_con->next = con_walker->next;
						} 
						else 
						{
							mapping_walker->conns = con_walker->next;
						}

						con_walker = con_walker->next;
						free(con_walker);
						continue;
					}

					pre_con = con_walker;
					con_walker = con_walker->next;
				}
			}         /* TCP mapping ends*/ 
			else if (mapping_walker->type == nat_mapping_icmp) 
			{
				if (difftime(curtime, mapping_walker->last_updated) > icmp_timeout) 
				{
					if (pre_mapping) 
					{
						pre_mapping->next = mapping_walker->next;
					}
					else
					{
						nat->mappings = mapping_walker->next;
					}

					mapping_walker = mapping_walker->next;
					free(mapping_walker);
					continue;
				}
			}

			pre_mapping = mapping_walker;
			mapping_walker = mapping_walker->next;
		}

		pthread_mutex_unlock(&(nat->lock));
	}
	return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) 
{

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  /*fprintf(stderr, "*** -> Looking for aux_ext = %d\n", ntohs(aux_ext));*/
  struct sr_nat_mapping *mapping_walker = nat->mappings;
  while (mapping_walker) 
  {
		/*fprintf(stderr, "*** -> Find NAT mapping with aux_ext = %d\n", ntohs(mapping_walker->aux_ext));*/
		if (mapping_walker->direction_type == INTER_MAP && mapping_walker->type == type && mapping_walker->aux_ext == aux_ext) 
		{
			/*fprintf(stderr, "Match!\n");*/
			break;
		}
		mapping_walker = mapping_walker->next;
  }

  if (mapping_walker) 
  {
		copy = (struct sr_nat_mapping*) malloc(sizeof(struct sr_nat_mapping));
		memcpy_byte_by_byte(copy, mapping_walker, sizeof(struct sr_nat_mapping));
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) 
{

	pthread_mutex_lock(&(nat->lock));

	/* handle lookup here, malloc and assign to copy. */
	struct sr_nat_mapping *copy = NULL;

	struct sr_nat_mapping *mapping_walker = nat->mappings;
	while (mapping_walker) 
	{
		if (mapping_walker->type == type && mapping_walker->aux_int == aux_int && mapping_walker->ip_int == ip_int) 
		{
			break;
		}
		mapping_walker = mapping_walker->next;
	}

	if (mapping_walker) 
	{
		copy = (struct sr_nat_mapping*) malloc(sizeof(struct sr_nat_mapping));
		memcpy_byte_by_byte(copy, mapping_walker, sizeof(struct sr_nat_mapping));
	}

	pthread_mutex_unlock(&(nat->lock));
	return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,uint32_t ip_int, uint32_t ip_ext, 
											 uint16_t aux_int, sr_nat_mapping_type type, sr_nat_mapping_direction_type direction_type, uint8_t *icmp_data) 
{

	pthread_mutex_lock(&(nat->lock));

	/* handle insert here, create a mapping, and then return a copy of it */
	struct sr_nat_mapping *copy = NULL;
	struct sr_nat_mapping *mapping = create_nat_mapping(type, direction_type, ip_int, ip_ext, aux_int, icmp_data);

	mapping->next = nat->mappings;
	nat->mappings = mapping;

	copy = (struct sr_nat_mapping*) malloc(sizeof(struct sr_nat_mapping));
	memcpy_byte_by_byte(copy, mapping, sizeof(struct sr_nat_mapping));

	pthread_mutex_unlock(&(nat->lock));

	return copy;
}

int nat_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */) {
/* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  struct sr_if *iface = sr_get_interface(sr, interface);
  assert(iface);

  struct sr_nat *nat = &(sr->nat);
  assert(nat);

  uint16_t ethtype = ethertype(packet);

  if (ethtype == ethertype_ip) {
    /* IP */
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    if (!ip_hdr) {
      return -1;
    }

    uint8_t ip_proto = ip_hdr->ip_p;
    if (ip_proto == ip_protocol_tcp) {
     
      uint16_t data_size = ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t) - sizeof(sr_tcp_hdr_t);

      sr_tcp_hdr_t *tcp_hdr = get_tcp_hdr(packet, len, data_size); 
      if (!tcp_hdr) {
        return -1;
      }

      int syn = ntohs(tcp_hdr->tcp_off) & TCP_SYN;
      int ack = ntohs(tcp_hdr->tcp_off) & TCP_ACK;
      int fin = ntohs(tcp_hdr->tcp_off) & TCP_FIN;
      int rst = ntohs(tcp_hdr->tcp_off) & TCP_RST;

      if (!strcmp(interface, INTER_IF)) {
        
        uint32_t ip_int = ip_hdr->ip_src;
        uint16_t aux_int = tcp_hdr->tcp_src_port;
        uint32_t ip_ext = sr_get_interface(sr, EXTER_IF)->ip;

        struct sr_nat_mapping *nat_mapping = sr_nat_lookup_internal(nat, ip_int, aux_int, nat_mapping_tcp);
        if (!nat_mapping) {
          /* Mapping not found for (ip, port), create new one */
          nat_mapping = sr_nat_insert_mapping(nat, ip_int, ip_ext, aux_int, nat_mapping_tcp, INTER_MAP, NULL);
        }
        uint16_t aux_ext = nat_mapping->aux_ext;
        uint32_t ip_remote = ip_hdr->ip_dst;
        uint16_t aux_remote = tcp_hdr->tcp_dest_port;

        update_tcp_conection(nat, ip_ext, aux_ext, ip_remote, aux_remote, syn, ack, fin, rst);

        /* Rewrite */
        ip_hdr->ip_src = ip_ext;
        tcp_hdr->tcp_src_port = aux_ext;

        memset(&(tcp_hdr->tcp_sum), 0, sizeof(uint16_t));

        sr_pseudo_tcp_hdr_t *pseudo_tcp_hdr = (sr_pseudo_tcp_hdr_t *) malloc(sizeof(sr_pseudo_tcp_hdr_t) + sizeof(sr_tcp_hdr_t) + data_size);
        pseudo_tcp_hdr->src_addr = ip_hdr->ip_src;
        pseudo_tcp_hdr->dst_addr = ip_hdr->ip_dst;
        pseudo_tcp_hdr->zeros = 0;
        pseudo_tcp_hdr->proto = ip_protocol_tcp;
        pseudo_tcp_hdr->tcp_len = htons(sizeof(sr_tcp_hdr_t) + data_size);

        memcpy_byte_by_byte(((uint8_t *) pseudo_tcp_hdr) + sizeof(sr_pseudo_tcp_hdr_t), tcp_hdr, sizeof(sr_tcp_hdr_t) + data_size);

        tcp_hdr->tcp_sum = cksum(pseudo_tcp_hdr, sizeof(sr_pseudo_tcp_hdr_t) + sizeof(sr_tcp_hdr_t) + data_size);
        memcpy_byte_by_byte(((uint8_t *) pseudo_tcp_hdr) + sizeof(sr_pseudo_tcp_hdr_t), tcp_hdr, sizeof(sr_tcp_hdr_t) + data_size);
        assert(cksum(pseudo_tcp_hdr, sizeof(sr_pseudo_tcp_hdr_t) + sizeof(sr_tcp_hdr_t) + data_size) == 65535);

        free(pseudo_tcp_hdr);
        free(nat_mapping);
      } else if (!strcmp(interface, EXTER_IF)) {
        
        uint16_t aux_ext = tcp_hdr->tcp_dest_port;
        uint32_t ip_remote = ip_hdr->ip_src;
        uint16_t aux_remote = tcp_hdr->tcp_src_port;
        uint32_t ip_ext = ip_hdr->ip_dst;

        struct sr_nat_mapping *nat_mapping = sr_nat_lookup_external(nat, aux_ext, nat_mapping_tcp);
        if (!nat_mapping) {
          uint8_t *icmp_data = (uint8_t *) malloc(ICMP_DATA_SIZE);
          memcpy_byte_by_byte(icmp_data, ip_hdr, ICMP_DATA_SIZE);
          sr_nat_insert_mapping(nat, 0, ip_remote, aux_ext, nat_mapping_tcp, EXTER_MAP, icmp_data);
          return 2;
         
        }

        update_tcp_conection(nat, ip_ext, aux_ext, ip_remote, aux_remote, syn, ack, fin, rst);

        /* Rewrite */
        ip_hdr->ip_dst = nat_mapping->ip_int;
        tcp_hdr->tcp_dest_port = nat_mapping->aux_int;

        memset(&(tcp_hdr->tcp_sum), 0, sizeof(uint16_t));

        sr_pseudo_tcp_hdr_t *pseudo_tcp_hdr = (sr_pseudo_tcp_hdr_t *) malloc(sizeof(sr_pseudo_tcp_hdr_t) + sizeof(sr_tcp_hdr_t) + data_size);
        pseudo_tcp_hdr->src_addr = ip_hdr->ip_src;
        pseudo_tcp_hdr->dst_addr = ip_hdr->ip_dst;
        pseudo_tcp_hdr->zeros = 0;
        pseudo_tcp_hdr->proto = ip_protocol_tcp;
        pseudo_tcp_hdr->tcp_len = htons(sizeof(sr_tcp_hdr_t) + data_size);

        memcpy_byte_by_byte(((uint8_t *) pseudo_tcp_hdr) + sizeof(sr_pseudo_tcp_hdr_t), tcp_hdr, sizeof(sr_tcp_hdr_t) + data_size);

        tcp_hdr->tcp_sum = cksum(pseudo_tcp_hdr, sizeof(sr_pseudo_tcp_hdr_t) + sizeof(sr_tcp_hdr_t) + data_size);
        memcpy_byte_by_byte(((uint8_t *) pseudo_tcp_hdr) + sizeof(sr_pseudo_tcp_hdr_t), tcp_hdr, sizeof(sr_tcp_hdr_t) + data_size);
        assert(cksum(pseudo_tcp_hdr, sizeof(sr_pseudo_tcp_hdr_t) + sizeof(sr_tcp_hdr_t) + data_size) == 65535);

        free(pseudo_tcp_hdr);
        free(nat_mapping);
      } else {
        fprintf(stderr, "Unknown interface\n");
        exit(1);
      }
    } else if (ip_proto == ip_protocol_icmp) {
      /* ICMP */
      
      uint16_t data_size = ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t) - sizeof(sr_icmp_hdr_t);

      sr_icmp_hdr_t *icmp_hdr = get_icmp_hdr(packet, len, data_size);

      if (!strcmp(interface, INTER_IF)) {
        /* Internal ICMP packet */
        
        uint32_t ip_int = ip_hdr->ip_src;
        uint16_t aux_int = icmp_hdr->icmp_id;
        uint32_t ip_ext = sr_get_interface(sr, EXTER_IF)->ip;

        struct sr_nat_mapping *nat_mapping = sr_nat_lookup_internal(nat, ip_int, aux_int, nat_mapping_icmp);
        if (!nat_mapping) {
          /* Mapping not found for (ip, port), create new one */
          nat_mapping = sr_nat_insert_mapping(nat, ip_int, ip_ext, aux_int, nat_mapping_icmp, INTER_MAP, NULL);
          
        }
        uint16_t aux_ext = nat_mapping->aux_ext;
        

        /* Rewrite */
        ip_hdr->ip_src = ip_ext;
        icmp_hdr->icmp_id = aux_ext;

        memset(&(icmp_hdr->icmp_sum), 0, sizeof(uint16_t));
        icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t) + data_size);

        free(nat_mapping);
      } else if (!strcmp(interface, EXTER_IF)) {
        /* External ICMP packet */
        
        uint16_t aux_ext = icmp_hdr->icmp_id;

        struct sr_nat_mapping *nat_mapping = sr_nat_lookup_external(nat, aux_ext, nat_mapping_icmp);
        if (!nat_mapping) {
         
          return 1;
        }

        /* Rewrite */
        ip_hdr->ip_dst = nat_mapping->ip_int;
        icmp_hdr->icmp_id = nat_mapping->aux_int;

        memset(&(icmp_hdr->icmp_sum), 0, sizeof(uint16_t));
        icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t) + data_size);

        free(nat_mapping);
      }
    } else if (ip_proto == ip_protocol_udp) {
      return 0;
    } else {
      return 0;
    }
  }

  return 0;
}

int nat_support(uint8_t * packet, unsigned int len) {
  uint16_t ethtype = ethertype(packet);

  if (ethtype == ethertype_ip) {
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    uint8_t ip_proto = ip_hdr->ip_p;
    if (ip_proto == ip_protocol_tcp) {
      return 1;
    } else if (ip_proto == ip_protocol_icmp) {
      uint16_t data_size = ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t) - sizeof(sr_icmp_hdr_t);
      sr_icmp_hdr_t *icmp_hdr = get_icmp_hdr(packet, len, data_size);

      if (icmp_hdr->icmp_type == 0 || icmp_hdr->icmp_type == 8) {
        return 1;
      }
    }
  }

  return 0;
}

struct sr_nat_mapping* create_nat_mapping(sr_nat_mapping_type type, sr_nat_mapping_direction_type direction_type, uint32_t ip_int, uint32_t ip_ext, uint16_t aux_int, uint8_t *icmp_data) 
{
	  struct sr_nat_mapping *mymapping = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));

	  mymapping->type = type;
	  mymapping->direction_type = direction_type;
	  mymapping->ip_int = ip_int;
	  mymapping->ip_ext = ip_ext;
	  mymapping->aux_int = aux_int;
	  mymapping->aux_ext = get_external_port(ip_int, aux_int);
	  mymapping->last_updated = time(NULL);
	  mymapping->conns = NULL;
	  mymapping->next = NULL;
	  mymapping->icmp_data = icmp_data;

	  return mymapping;
}








