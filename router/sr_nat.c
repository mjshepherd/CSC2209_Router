
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
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;

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

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
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
