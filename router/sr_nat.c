
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "sr_nat.h"


int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

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
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext) {

    pthread_mutex_lock(&(nat->lock));

    /* handle lookup here, malloc and assign to copy */
    struct sr_nat_mapping *copy = NULL;
  
    fprintf(stderr, "INFO: Looking for aux_ext = %d\n", ntohs(aux_ext));
    struct sr_nat_mapping *mapping_walker = nat->mappings;
    while (mapping_walker) 
    {
        if (mapping_walker->aux_ext == aux_ext) 
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
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;
  struct sr_nat_mapping *mapping = create_nat_mapping(type, ip_int, ip_ext, aux_int);

  mapping->next = nat->mappings;
  nat->mappings = mapping;

  copy = (struct sr_nat_mapping*) malloc(sizeof(struct sr_nat_mapping));
  memcpy(copy, mapping, sizeof(struct sr_nat_mapping)); 
  
  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}

struct sr_nat_mapping* create_nat_mapping(sr_nat_mapping_type type, uint32_t ip_int, uint32_t ip_ext, uint16_t aux_int) {
  struct sr_nat_mapping *result = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));

  result->type = type;
  result->direction_type = direction_type;
  result->ip_int = ip_int;
  result->ip_ext = ip_ext;
  result->aux_int = aux_int;
  result->aux_ext = calculate_external_port(ip_int, aux_int);
  result->last_updated = time(NULL);
  result->conns = NULL;
  result->next = NULL;
  result->packet_data = packet;

  return result;
}

uint16_t calculate_external_port(uint32_t ip_int, uint16_t aux_int) {
  uint16_t result = (ip_int + aux_int) % MAX_PORT_NUM;

  if (result < 1024) {
    result += 1024;
  }

  return result;
}

struct sr_nat_connection* create_connection(int32_t ip_ext, uint16_t aux_ext, 
  uint32_t ip_remote, uint16_t aux_remote) {

  fprintf(stderr, "INFO:  Creating new connection!\n");
  struct sr_nat_connection *result = (struct sr_nat_connection *) malloc(sizeof(struct sr_nat_connection));

  result->ip_ext = ip_ext;
  result->aux_ext = aux_ext;
  result->ip_remote = ip_remote;
  result->aux_remote = aux_remote;
  result->state = TRANS;

  return result;
}

sr_nat_tcp_state calculate_tcp_state(int syn, int ack, int fin, int rst) {
  if (fin || syn || rst) {
      return TRANS;
  } else if (ack) {
    return ESTAB;
  }
  return TRANS;
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

  fprintf(stderr, "Looking for conection with ip_ext =  %d, aux_ext = %d, ip_remote = %d, aux_remote = %d\n", 
    ntohl(ip_ext), ntohs(aux_ext), ntohl(ip_remote), ntohs(aux_remote));

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
          nat_mapping = sr_nat_insert_mapping(nat, ip_int, ip_ext, aux_int, nat_mapping_tcp, INTERNAL, NULL);
        }
        uint16_t aux_ext = nat_mapping->aux_ext;
        uint32_t ip_remote = ip_hdr->ip_dst;
        uint16_t aux_remote = tcp_hdr->tcp_dest_port;

        update_tcp_conection(nat, ip_ext, aux_ext, ip_remote, aux_remote, syn, ack, fin, rst);

        /* Rewrite */
        ip_hdr->ip_src = ip_ext;
        tcp_hdr->tcp_src_port = aux_ext;
        
        /* Compute new checksum */
        sr_create_tcp_checksum(packet, len);
        
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

        /* Compute new checksum */
        sr_create_tcp_checksum(packet, len);
        
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
          nat_mapping = sr_nat_insert_mapping(nat, ip_int, ip_ext, aux_int, nat_mapping_icmp, INTERNAL, NULL);
          
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

/* Recomputes the checksum field in the packet's tcp header. Does not check the previous checksum */
void sr_create_tcp_checksum(uint8_t *packet, unsigned int len) {
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
        sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *) (&ip_hdr + sizeof(sr_ip_hdr_t));
       
        memset(&(tcp_hdr->tcp_sum), 0, sizeof(uint16_t));
        
        struct sr_pseudo_tcp_hdr_t *pseudo_tcp_hdr;
        pseudo_tcp_hdr->src_addr = ip_hdr->ip_src;
        pseudo_tcp_hdr->dst_addr = ip_hdr->ip_dst;
        pseudo_tcp_hdr->zeros = 0;
        pseudo_tcp_hdr->proto = ip_protocol_tcp;
        pseudo_tcp_hdr->tcp_len = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);

        int bufferSize = sizeof(sr_psude_tcp_hdr_t) + len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
        uint8_t *buffer = malloc(sizeof(bufferSize));
        
        /*Copy pseudoheader, tcp header and data into the buffer */
        memcpy(buffer, pseudo_tcp_hdr, sizeof(sr_pseudo_tcp_hdr_t);
        memcpy(buffer + sizeof(sr_pseudo_hdr_t), packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), pseduo_tcp_hdr->tcp_len);

        tcp_hdr->tcp_sum = cksum(buffer, bufferSize);
        
        free(buffer);
}

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
                if (mapping_walker->direction_type == EXTERNAL && conn_walker->state == TRANS) {
                    if (difftime(curtime, mapping_walker->last_updated) > 6.0) {
                       /* - TODO: This branch will be executed when an unsolicited inboud syn packet has not been responded to in 6 seconds.
                       The code should remove the connection and send an ICMP type 3 code 3 to the source specified in the unacked packet. */                       continue;
                    }
                    /* TODO: This should check for any outbound SYN packets. If one is found, it should silently drop any unsolicited 
                    inbound SYN packets. Unsure if this is where this should be done. A safer bet would be to drop unsolicited inbound 
                    S packets when a new connection is opened... */
                }
                /* Check for inactive connections and drop if needed */
                double timediff = difftime(curtime, conn_walker->last_updated);
                if( (conn_walker->state == ESTAB && timediff > tcp_establish_timeout) || (conn_walker->state == TRANS && timediff > tcp_trans_timeout)) {
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
        else if (mapping_walker->type = nat_mapping_icmp && (difftime(mapping_walker->last_updated, curtime) > icmp_timeout)) {
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
