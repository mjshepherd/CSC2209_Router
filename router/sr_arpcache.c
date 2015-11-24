#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    struct sr_arpreq *arpreq_walker = sr->cache.requests;

    while (arpreq_walker) {
        struct sr_arpreq *arpreq_walker_next = arpreq_walker->next;
        handle_arpreq(sr, arpreq_walker);
        arpreq_walker = arpreq_walker_next;
    }
}


void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *sr_arpreq) {
  time_t now = time(0);

  if (now - sr_arpreq->sent > 1.0) {
    if (sr_arpreq->times_sent >= 5) {
      struct sr_packet *packet_walker = sr_arpreq->packets;
      while (packet_walker) {
        /* Send ICMP destination host unreachable to the sender of each packet */
        uint8_t *buf = packet_walker->buf;
        unsigned int len = packet_walker->len;

        if (len < sizeof(sr_ethernet_hdr_t)) {
          fprintf(stderr, "Failed to handle the packet due to insufficient length, drop it\n");
          packet_walker = packet_walker->next;
          continue;
        };

        uint16_t ethtype = ethertype(buf);
        sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *) buf;

        if (ethtype != ethertype_ip) {
          fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
          packet_walker = packet_walker->next;
          continue;
        }

        uint8_t *ether_shost_icmp = ethernet_hdr->ether_dhost;

        char *outgoing_iface = find_if_by_mac(sr, ether_shost_icmp);
        if (!outgoing_iface) {
          fprintf(stderr, "Cannot find outgoing interface\n");
          packet_walker = packet_walker->next;
          continue;
        }

        sr_ip_hdr_t *ip_hdr = get_ip_hdr(buf, len);
        if (!ip_hdr) {
          packet_walker = packet_walker->next;
          continue;
        }

        uint32_t ip_dst_icmp = ntohl(ip_hdr->ip_src);

        /* TODO fix */ 
        void *icmp_data = malloc(ICMP_DATA_SIZE);
        memcpy_byte_by_byte(icmp_data, ip_hdr, ICMP_DATA_SIZE);

        unsigned int length = 0;
        uint8_t *icmp_packet = create_icmp_packet(sr, 3, 1, 0, 0, ip_dst_icmp, ICMP_DATA_SIZE, icmp_data, &length);
        if (icmp_packet) {
          send_packet(sr, icmp_packet, length, icmp_data);
        }

        packet_walker = packet_walker->next;

        free(icmp_data);
      }
      sr_arpreq_destroy(&(sr->cache), sr_arpreq);
    } else {
      /* Send the ARP request */
      struct sr_rt* rt = sr_get_rt_by_gateway(sr, sr_arpreq->ip);
      if (!rt) {
        fprintf(stderr, "Failed to find entry in routing table for ARP request\n");
        return;
      }

      struct sr_if* sr_if = sr_get_interface(sr, rt->interface);
      if (!sr_if) {
        fprintf(stderr, "Failed to find interface for ARP request\n");
        return;
      }

      sr_arp_hdr_t *arp_req = create_arp_req_hdr(sr, sr_arpreq, sr_if);
      if (!arp_req) {
        return;
      }

      uint8_t *arp_packet = create_ethernet_hdr((uint8_t *) arp_req, arp_req->ar_tha, arp_req->ar_sha, sizeof(sr_arp_hdr_t), ethertype_arp);
      sr_send_packet(sr, (uint8_t *) arp_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), sr_if->name);

      sr_arpreq->sent = now;
      sr_arpreq->times_sent++;
    }
  }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}


struct sr_rt* sr_get_rt_by_gateway(struct sr_instance* sr, uint32_t gateway) {
  
  struct sr_rt *rt_walker = sr->routing_table;

  while(rt_walker) {
    if (rt_walker->gw.s_addr == gateway) {
      return rt_walker;
    }
    rt_walker = rt_walker->next;
  }

  return 0;
}


sr_arp_hdr_t *verify_arp_hdr(uint8_t *packet, unsigned int len) {
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
    fprintf(stderr, "Failed to handle the ARP packet due to insufficient length, drop it\n");
    return 0;
  }

  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

  return arp_hdr;
}

char* find_if_by_mac(struct sr_instance* sr, uint8_t *ether_shost) {
  struct sr_if* if_walker = sr->if_list;

  while (if_walker) {
    int i;
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
      if (if_walker->addr[i] != ether_shost[i]) {
        break;
      } else if (i == ETHER_ADDR_LEN - 1) {
        return if_walker->name;
      }
    }
    if_walker = if_walker->next;
  }
  return 0;
}
