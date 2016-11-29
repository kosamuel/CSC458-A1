
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include "sr_if.h"
#include <stdlib.h>
#include <string.h>
#include "sr_router.h"

uint16_t port_num = 5000;

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
    /*struct sr_nat_mapping *mapping, *prev = NULL, *next = NULL, *free_mapping = NULL;
    mapping = nat->mappings;
    while (mapping != NULL) {
      /* ICMP */
      /*if (mapping->type == nat_mapping_icmp) {
        if (difftime(curtime,mapping->last_updated) > nat->icmp_timeout) { 
            if (prev) {
              next = mapping->next;
              prev->next = next;
            } else {
              next = mapping->next;
              nat->mappings = next;
            }

            free_mapping = mapping;
            mapping = mapping->next;
            free(free_mapping);

        } else {
          mapping = mapping->next;
        }

      /* TCP */
      /*} /*else if (mapping->type == nat_mapping_tcp) {

        struct sr_nat_connection *conn, *cprev = NULL, *cnext = NULL, *free_conn = NULL;
        while (conn != NULL) {
          if (cprev) {
            cnext = 
          }

        }
      }
    } */

    /*struct sr_nat_mapping *mapping, *prev = NULL, *next = NULL; 
        for (mapping = nat->mappings; mapping != NULL; mapping = mapping->next) {
            if (difftime(curtime,mapping->last_updated) > nat->icmp_timeout &&
                mapping->type == nat_mapping_icmp) {                
                if (prev) {
                    next = mapping->next;
                    prev->next = next;
                } 
                else {
                    next = mapping->next;
                    nat->mappings = next;
                }

                free(mapping);
              
            }
            prev = mapping;
        }*//* else if (mapping->type == tcp) {

        sr_nat_connection_state established = EST;
        struct sr_nat_connection *conn;
        struct sr_nat_connection *prev_conn = NULL;

        for (conn = mapping->conns; conn != NULL; conn = conn->next) {

          if (conn->current_state == established) {
            if (difftime(curtime,conn->last_updated) > nat->established_timeout) {
              if (prev_conn) {
                prev_conn->next = conn->next;
                free(conn);
                conn = prev_conn;

              } else {
                mapping->conns = conn->next;
                free(conn);
                conn = mapping->conns;

              }

            } else {
              prev_conn = conn;

            }

          } else if (conn->current_state != established) {
            if (difftime(curtime,conn->last_updated) > nat->transitory_timeout) {
              if (prev_conn) {
                prev_conn->next = conn->next;
                free(conn);
                conn = prev_conn;

              } else {
                mapping->conns = conn->next;
                free(conn);
                conn = mapping->conns;

              }

            } else {
              prev_conn = conn;

            }
            
          } else if (conn->current_state == CLOSED) {
            if (prev_conn) {
              prev_conn->next = conn->next;
              free(conn);
              conn = prev_conn;

            } else {
              mapping->conns = conn->next;
              free(conn);
              conn = mapping->conns;

            }

          } 
        }*/


        /* Check if removing a connection makes the connection list empty */
        /*if (mapping->conns == NULL) {


          if (difftime(curtime,mapping->last_updated) > nat->icmp_timeout) {*/
          
            /* Make previous mapping link to mapping->next */
            /*if (prev) {
              prev->next = mapping->next;
              free(mapping);
              mapping = prev;

            } else {
              nat->mappings = mapping->next;
              free(mapping);
              mapping = nat->mappings;

            }

          } else {
            prev = mapping;

          }
        }
      }
    }*/

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
  struct sr_nat_mapping *entry = NULL, *copy = NULL;

  struct sr_nat_mapping *mapping;
  for (mapping = nat->mappings; mapping != NULL; mapping = mapping->next) {
      if (mapping->aux_ext == aux_ext && mapping->type == type) {
          entry = mapping;
          break;
      }
  }
  
  /* Must return a copy b/c another thread could jump in and modify
     table after we return. */
  if (entry) {
      copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, entry, sizeof(struct sr_nat_mapping));
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
  struct sr_nat_mapping *entry = NULL, *copy = NULL;

  struct sr_nat_mapping *mapping;
  for (mapping = nat->mappings; mapping != NULL; mapping = mapping->next) {
      if ((mapping->aux_int == aux_int) && (mapping->ip_int == ip_int) && (mapping->type == type)) {
          entry = mapping;
          break;
      }
  }
  
  /* Must return a copy b/c another thread could jump in and modify
     table after we return. */
  if (entry) {
      copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, entry, sizeof(struct sr_nat_mapping));
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_instance* sr, struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;

  struct sr_nat_mapping *new_mapping = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));

  /* Set up the new mapping */
  struct sr_if *iface = sr_get_interface(sr, "eth2");
  new_mapping->type = type;
  new_mapping->ip_int = ip_int;
  new_mapping->ip_ext = iface->ip;
  new_mapping->aux_int = aux_int;
  new_mapping->aux_ext = port_num;
  new_mapping->last_updated = time(NULL);

  /* Initialize connection */
  struct sr_nat_connection *conn = NULL;
  new_mapping->conns = conn;

  /* Add to exisiting list of mappings */
  if (nat->mappings != NULL) {
    new_mapping->next = nat->mappings->next;
    nat->mappings = new_mapping;
  } else {
    new_mapping->next = NULL;
    nat->mappings = new_mapping;
  }

  /* Update port number */
  port_num++;

  /* Make a new copy of the mapping and return it */
  mapping = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
  memcpy(mapping, new_mapping, sizeof(struct sr_nat_mapping));

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}

void insert_connection(struct sr_nat_mapping *mapping, uint32_t ip_ext, uint16_t port_ext) {
  struct sr_nat_connection *new_conn = (struct sr_nat_connection *) malloc(sizeof(struct sr_nat_connection));
  new_conn->current_state = SYN;
  new_conn->next_state = SYNACK;
  new_conn->ip_ext = ip_ext;
  new_conn->aux_ext = port_ext;
  new_conn->last_updated = time(NULL);

  new_conn->next = mapping->conns;
  mapping->conns = new_conn;

}
