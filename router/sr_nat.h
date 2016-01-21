
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

#define MAX_PORT_NUMBER 65536
#define INT_IF "eth1"
#define EXT_IF "eth2"

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum {
  ESTAB,
  TRANS,
  UNSOLICITED
} sr_nat_tcp_state;

typedef enum {
  INT_TO_EXT,
  EXT_TO_INT
} sr_nat_tcp_flow_dir;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  sr_nat_tcp_state state; /*The current state of the connection */
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */ 
  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;

  sr_nat_mapping_direction_type direction_type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
  uint8_t *icmp_data;
};

struct sr_nat {
  struct sr_instance *sr;
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  unsigned int icmp_timeout;
  unsigned int tcp_establish_timeout;
  unsigned int tcp_trans_timeout;

  unsigned int icmp_timeout;
  unsigned int tcp_establish_timeout;
  unsigned int tcp_trans_timeout;
  uint32_t ip_ext;
  struct sr_instance *sr;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );


/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint32_t ip_ext, uint16_t aux_int, sr_nat_mapping_type type);

struct sr_nat_mapping* create_nat_mapping(sr_nat_mapping_type type, uint32_t ip_int, uint32_t ip_ext, uint16_t aux_int);

uint16_t calculate_external_port(uint32_t ip_int, uint16_t aux_int);

struct sr_nat_connection* create_connection(int32_t ip_ext, uint16_t aux_ext, uint32_t ip_int, uint16_t aux_int);

sr_nat_tcp_state calculate_tcp_state(int syn, int ack, int fin, int rst, sr_nat_tcp_flow_dir dir);

void update_tcp_conection(struct sr_nat *nat, uint32_t ip_ext, uint16_t aux_ext, uint32_t ip_int, uint16_t aux_int, 
                          int syn, int ack, int fin, int rst, sr_nat_tcp_flow_dir dir);

int sr_nat_translate_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface/* lent */);

/* NAT cron job. Runs every second and is used to clean defunct mappings */
void sr_nat_clean(struct sr_nat *nat, time_t time);
#endif
