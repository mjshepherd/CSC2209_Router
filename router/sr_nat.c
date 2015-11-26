
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_utils.h"
#include "sr_nat.h"

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */
  fprintf(stderr, "INFO: Initializing NAT...\n");
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


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);
    /* handle periodic tasks here */
    sr_nat_clean(nat, time);

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
/*NOTE: For now the lookup checks that the mapping type is equivalent to the 
 * given type; I don't think that this is required*/
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

    pthread_mutex_lock(&(nat->lock));

    /* handle lookup here, malloc and assign to copy */
    struct sr_nat_mapping *copy = NULL;
  
    fprintf(stderr, "INFO: Looking for aux_ext = %d\n", ntohs(aux_ext));
    struct sr_nat_mapping *mapping_walker = nat->mappings;
    while (mapping_walker) 
    {
        if (mapping_walker->type == type && mapping_walker->aux_ext == aux_ext) 
        {
            fprintf(stderr, "INFO: Found NAT mapping with aux_ext = %d\n", ntohs(mapping_walker->aux_ext));
            break;
        }
        mapping_walker = mapping_walker->next;
    }

    if (mapping_walker) 
    {
        copy = (struct sr_nat_mapping*) malloc(sizeof(struct sr_nat_mapping));
        memcpy(copy, mapping_walker, sizeof(struct sr_nat_mapping));
    } 
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

    pthread_mutex_lock(&(nat->lock));

    /* handle lookup here, malloc and assign to copy. */
    struct sr_nat_mapping *copy = NULL;
    
    fprintf(stderr, "INFO: Looking for aux_int = %d\n", ntohs(aux_int));
    struct sr_nat_mapping *mapping_walker = nat->mappings;
    while (mapping_walker) 
    {
        if (mapping_walker->type == type && mapping_walker->aux_int == aux_int && mapping_walker->ip_int == ip_int) 
        {
            fprintf(stderr, "INFO: Found NAT mapping with aux_int = %d\n", ntohs(mapping_walker->aux_int));
            break;
        }
        mapping_walker = mapping_walker->next;
    }

    if (mapping_walker) 
    {
        copy = (struct sr_nat_mapping*) malloc(sizeof(struct sr_nat_mapping));
        memcpy(copy, mapping_walker, sizeof(struct sr_nat_mapping));
    }
    pthread_mutex_unlock(&(nat->lock));
    return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint32_t ip_ext, uint16_t aux_int, sr_nat_mapping_type type) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = create_nat_mapping(type, ip_int, ip_ext, aux_int);

  mapping->next = nat->mappings;
  nat->mappings = mapping;
  
  fprintf(stderr, "INFO:Inserted a new mapping entry into the mapping table with the following info:  ip_ext =  %d, aux_ext = %d, ip_int = %d, aux_int = %d\n",
            ntohl(mapping->ip_ext), ntohs(mapping->aux_ext), ntohl(mapping->ip_int), ntohs(mapping->aux_int));
  struct sr_nat_mapping* copy = (struct sr_nat_mapping*) malloc(sizeof(struct sr_nat_mapping));
  memcpy(copy, mapping, sizeof(struct sr_nat_mapping)); 
  
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

struct sr_nat_mapping* create_nat_mapping(sr_nat_mapping_type type, uint32_t ip_int, uint32_t ip_ext, uint16_t aux_int) {
  struct sr_nat_mapping *result = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));

  result->type = type;
 result->ip_int = ip_int;
  result->ip_ext = ip_ext;
  result->aux_int = aux_int;
  result->aux_ext = calculate_external_port(ip_int, aux_int);
  result->last_updated = time(NULL);
  result->conns = NULL;
  result->next = NULL;

  return result;
}

uint16_t calculate_external_port(uint32_t ip_int, uint16_t aux_int) {
  uint16_t result = (ip_int + aux_int) % MAX_PORT_NUMBER;

  if (result < 1024) {
    result += 1024;
  }

  return result;
}

struct sr_nat_connection* create_connection(int32_t ip_ext, uint16_t aux_ext, uint32_t ip_int, uint16_t aux_int) {

  fprintf(stderr, "INFO:  Creating new connection!\n");
  struct sr_nat_connection *result = (struct sr_nat_connection *) malloc(sizeof(struct sr_nat_connection));

  result->ip_ext = ip_ext;
  result->aux_ext = aux_ext;
  result->ip_int = ip_int;
  result->aux_ext = aux_ext;
  result->state = TRANS;
  result->last_updated = time(NULL);
  assert(result);
  return result;
}

sr_nat_tcp_state calculate_tcp_state(int syn, int ack, int fin, int rst, sr_nat_tcp_flow_dir dir) {
  if (fin || syn || rst) {
      if ( syn && dir == EXT_TO_INT ) {
        return UNSOLICITED;
      }
      return TRANS;
  } else if (ack) {
    return ESTAB;
  }
  return TRANS;
}

void update_tcp_conection(struct sr_nat *nat, uint32_t ip_ext, uint16_t aux_ext, uint32_t ip_int, uint16_t aux_int, int syn, int ack, int fin, int rst, sr_nat_tcp_flow_dir dir) 
{
  /* Requires */
  assert(nat);
  
  fprintf(stderr, "INFO: Updating the connection with the following info:  ip_ext =  %d, aux_ext = %d, ip_int = %d, aux_int = %d\n",
      ntohl(ip_ext), ntohs(aux_ext), ntohl(ip_int), ntohs(aux_int));
  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_mapping *mapping = NULL;
  struct sr_nat_mapping *mapping_walker = nat->mappings;
  while(mapping_walker) {

    if (mapping_walker->ip_int == ip_int && mapping_walker->aux_int == aux_int && mapping_walker->type == nat_mapping_tcp) {
      mapping = mapping_walker;
      break;
    }
    mapping_walker = mapping_walker->next;
  }

  assert(mapping);

  struct sr_nat_connection *con_walker = mapping->conns;

  int updated = 0;
  while (con_walker) 
  {
    if (con_walker->ip_ext == ip_ext &&
      con_walker->aux_ext == aux_ext &&
      con_walker->ip_int == ip_int &&
      con_walker->aux_int == aux_int) 
    {
      con_walker->state = calculate_tcp_state(syn, ack, fin, rst, dir);
      con_walker->last_updated = time(NULL);
      updated = 1;
    }
    con_walker = con_walker->next;
  }

  if (!updated) 
  {
    fprintf(stderr, "INFO: No connection was found, creating a new one\n");
    con_walker = create_connection( ip_ext, aux_ext, ip_int, aux_int);
    assert(con_walker);
    con_walker->state = calculate_tcp_state(syn, ack, fin, rst, dir);
    con_walker->next = mapping->conns;
    mapping->conns = con_walker;
  }

  pthread_mutex_unlock(&(nat->lock));
}

int sr_nat_translate_packet(struct sr_instance* sr,
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

    uint8_t ip_proto = ip_hdr->ip_p;
    if (ip_proto == ip_protocol_tcp) {
     
      uint16_t data_size = ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t) - sizeof(sr_tcp_hdr_t);

      sr_tcp_hdr_t *tcp_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)); 

      int syn = ntohs(tcp_hdr->tcp_off) & TCP_SYN;
      int ack = ntohs(tcp_hdr->tcp_off) & TCP_ACK;
      int fin = ntohs(tcp_hdr->tcp_off) & TCP_FIN;
      int rst = ntohs(tcp_hdr->tcp_off) & TCP_RST;

      if (!strcmp(interface, INT_IF)) {
        
        uint32_t ip_int = ip_hdr->ip_src;
        uint16_t aux_int = tcp_hdr->tcp_src_port;
        uint32_t ip_ext = sr_get_interface(sr, EXT_IF)->ip;
        struct sr_nat_mapping *nat_mapping = sr_nat_lookup_internal(nat, ip_int, aux_int, nat_mapping_tcp);
        if (!nat_mapping) {
          /* Mapping not found for (ip, port), create new one */
          fprintf(stderr, "INFO: Failed to find a mapping, creating a new one... \n");
          nat_mapping = sr_nat_insert_mapping(nat, ip_int, ip_ext, aux_int, nat_mapping_tcp);
        }
        uint16_t aux_ext = nat_mapping->aux_ext;
        uint32_t ip_dst = ip_hdr->ip_dst;
        uint16_t aux_dst = tcp_hdr->tcp_dest_port;

        update_tcp_conection(nat, ip_dst, aux_dst, ip_int, aux_int, syn, ack, fin, rst, INT_TO_EXT);
        
        fprintf(stderr, "INFO: TCP connection has been updated. Re-writing packet \n");
        /* Rewrite */
        ip_hdr->ip_src = ip_ext;
        tcp_hdr->tcp_src_port = aux_ext;
        
        /* Compute new checksum */
        sr_create_tcp_checksum(packet, len);
        
        free(nat_mapping);
        fprintf(stderr, "INFO: Finished translating. \n");
        return 1;
      } else if (!strcmp(interface, EXT_IF)) {
        
        uint16_t aux_ext = tcp_hdr->tcp_dest_port;
        uint32_t ip_remote = ip_hdr->ip_src;
        uint16_t aux_remote = tcp_hdr->tcp_src_port;
        uint32_t ip_ext = ip_hdr->ip_dst;
        
        struct sr_nat_mapping *nat_mapping = sr_nat_lookup_external(nat, aux_ext, nat_mapping_tcp);
        if (!nat_mapping) {
          /* TODO: This is a very odd case. The nat recieves an external tcp packet but doesn't have a mapping for it... 
          This should definitely return here since we do not know the internal ip or port*/
          fprintf(stderr, "WARNING: No mapping exists for the inbound TCP packet...\n");
          return -1;
        }
        
        /* NOTE: By specifying the direction type a connection may be marked as UNSOLICITED and cleaned after six seconds */
        update_tcp_conection(nat, ip_remote, aux_remote, nat_mapping->ip_int, nat_mapping->aux_int, syn, ack, fin, rst, EXT_TO_INT);

        /* Rewrite */
        ip_hdr->ip_dst = nat_mapping->ip_int;
        tcp_hdr->tcp_dest_port = nat_mapping->aux_int;

        /* Compute new checksum */
        sr_create_tcp_checksum(packet, len);
        
        free(nat_mapping);
        return 1;
      } else {
        fprintf(stderr, "Unknown interface\n");
        exit(1);
      }
    } else if (ip_proto == ip_protocol_icmp) {
      /* ICMP */
      
      uint16_t data_size = ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t) - sizeof(sr_icmp_hdr_t);

      sr_icmp_r_hdr_t * icmp_hdr = (sr_icmp_r_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      
      if (!strcmp(interface, INT_IF)) {
        /* Internal to External ICMP packet*/
        
        /* First check to see if the destination is one of the router's interfaces. If it is DO NOT TRANSLATE */
        if ( ip_hdr->ip_dst == sr_get_interface(sr, INT_IF)->ip || ip_hdr->ip_dst == sr_get_interface(sr, EXT_IF)->ip) {
            fprintf(stderr, "INFO:NAT: ICMP packet was destined for on of the router's interfaces. Not translating. \n");
            return 0;
        }
        uint32_t ip_int = ip_hdr->ip_src;
        uint16_t aux_int = icmp_hdr->icmp_id;
        uint32_t ip_ext = sr_get_interface(sr, EXT_IF)->ip;

        struct sr_nat_mapping *nat_mapping = sr_nat_lookup_internal(nat, ip_int, aux_int, nat_mapping_icmp);
        if (!nat_mapping) {
          /* Mapping not found for (ip, port), create new one */
          nat_mapping = sr_nat_insert_mapping(nat, ip_int, ip_ext, aux_int, nat_mapping_icmp);
        }
        uint16_t aux_ext = nat_mapping->aux_ext;
        

        /* Rewrite */
        ip_hdr->ip_src = ip_ext;
        icmp_hdr->icmp_id = aux_ext;
        
        icmp_hdr->icmp_sum = 0;
        icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t) + data_size);

        free(nat_mapping);
        return 1;
      } else if (!strcmp(interface, EXT_IF)) {
        /* External ICMP packet */
        
        uint16_t aux_ext = icmp_hdr->icmp_id;

        struct sr_nat_mapping *nat_mapping = sr_nat_lookup_external(nat, aux_ext, nat_mapping_icmp);
        if (!nat_mapping) {
          return 0;
        }

        /* Rewrite */
        ip_hdr->ip_dst = nat_mapping->ip_int;
        icmp_hdr->icmp_id = nat_mapping->aux_int;

        icmp_hdr->icmp_sum = 0;
        icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl*4);

        free(nat_mapping);
        return 1;
      }
    } else if (ip_proto == ip_protocol_udp) {
      return 0;
    } else {
      return 0;
    }
  }

  return 0;
}

/* Recomputes the checksum field in the packet's tcp header. Does not check the previous checksum */
void sr_create_tcp_checksum(uint8_t *packet, unsigned int len) {
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
        sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *) (&ip_hdr + sizeof(sr_ip_hdr_t));
       
        memset(&(tcp_hdr->tcp_sum), 0, sizeof(uint16_t));
        sr_pseudo_tcp_hdr_t *pseudo_tcp_hdr = (sr_pseudo_tcp_hdr_t *) malloc(sizeof(sr_pseudo_tcp_hdr_t)); 
        pseudo_tcp_hdr->src_addr = ip_hdr->ip_src;
        pseudo_tcp_hdr->dst_addr = ip_hdr->ip_dst;
        pseudo_tcp_hdr->zeros = 0;
        pseudo_tcp_hdr->ip_proto = ip_protocol_tcp;
        pseudo_tcp_hdr->tcp_len = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);

        int bufferSize = sizeof(sr_pseudo_tcp_hdr_t) + len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
        uint8_t *buffer = malloc(bufferSize);
        
        /*Copy pseudoheader, tcp header and data into the buffer */
        memcpy(buffer, pseudo_tcp_hdr, sizeof(sr_pseudo_tcp_hdr_t));
        memcpy(buffer + sizeof(sr_pseudo_tcp_hdr_t), packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), pseudo_tcp_hdr->tcp_len);

        tcp_hdr->tcp_sum = cksum(buffer, bufferSize);
        fprintf(stderr, "INFO: Checksum calculated \n"); 
        free(buffer);
        free(pseudo_tcp_hdr);
}

/* Periodic cleaning of the NAT */
void sr_nat_clean(struct sr_nat *nat, time_t curtime) {
    struct sr_nat_mapping *mapping_walker = nat->mappings;
    struct sr_nat_mapping *previous_mapping = NULL;
    while (mapping_walker) {
        if (mapping_walker->type = nat_mapping_tcp) {
            struct sr_nat_connection* conn_walker = mapping_walker->conns;
            struct sr_nat_connection* prev_conn = NULL;
            /* If no connections exist then we can free the mapping */
            if (!conn_walker) {
                if(previous_mapping) {
                    previous_mapping->next = mapping_walker->next;
                    free(mapping_walker);
                    mapping_walker = previous_mapping->next;
                } else {
                    nat->mappings = mapping_walker->next;
                    free(mapping_walker);
                    mapping_walker = nat->mappings;
                }
                continue;
            }
            while (conn_walker) {
                /* First lets clean any unsolicited inbound SYN packets TODO: Unsure if this is the proper way to check for an inbound syn
                    packet. We may want to add a new connection state SYN to confirm */
                if (conn_walker->state == UNSOLICITED) {
                    if (difftime(curtime, mapping_walker->last_updated) > 6.0) {
                       /* - TODO: This branch will be executed when an unsolicited inboud syn packet has not been responded to in 6 seconds.
                       The code should remove the connection and send an ICMP type 3 code 3 to the source specified in the unacked packet. */                       continue;
                    }
                }
                /* Check for inactive connections and drop if needed */
                double timediff = difftime(curtime, conn_walker->last_updated);
                if( (conn_walker->state == ESTAB && timediff > nat->tcp_establish_timeout) || (conn_walker->state == TRANS && timediff > nat->tcp_trans_timeout)) {
                    if (prev_conn) {
                        prev_conn->next = conn_walker->next;
                        free(conn_walker);
                        conn_walker = prev_conn->next;
                    } else {
                        mapping_walker->conns = conn_walker->next;
                        free(conn_walker);
                        conn_walker = mapping_walker->conns;
                    }
                    continue;
                }

                prev_conn = conn_walker;
                conn_walker = conn_walker->next;
            }/* End of conn walker loop */
        } /* End of if mapping_walker is type TCP */
        else if (mapping_walker->type = nat_mapping_icmp && (difftime(mapping_walker->last_updated, curtime) > nat->icmp_timeout)) {
            if (previous_mapping) {
                previous_mapping->next = mapping_walker->next;
                free(mapping_walker);
                mapping_walker = previous_mapping->next;
            } else {
                nat->mappings = mapping_walker->next;
                free(mapping_walker);
                mapping_walker = nat->mappings;
            }
            continue;
        } /* End of if mapping_walker is type ICMP */
        
        previous_mapping = mapping_walker;
        mapping_walker = mapping_walker->next;
    }/* End of mapping_walker loop */
}/* EOF sr_nat_clean */
