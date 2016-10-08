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

  /* fill in code here */
  /* The received packet is an arp packet.*/
  if (packet[12] == 0x08 && packet[13] == 0x06) {
    handle_arppacket(sr, packet);
  }

}/* end sr_ForwardPacket */

void handle_arppacket(struct sr_instance* sr,
                      uint8_t * packet) {
  /* The packet is an arp request. */
  if (packet[21] == 0x01) {
    struct sr_arpreq *req;
    uint8_t buf[4];
    memcpy(buf, packet[34], 4);
    uint32_t ip = 8bit_32bit_conversion(buf);

    for (req = sr->cache->requests; req != NULL; req = req->next) {
      if ()

  /* The packet is an arp reply. */
  } else if (packet[21] == 0x02) {

  }
}

/* Converts a uint8_t array into a uint32_t. */
uint32_t 8bit_32bit_conversion(uint8_t[4] bytes) {
  int i;
  uint32_t 32bit = 0x0000;

  for (i = 0; i < 4; i++) {
    32bit = (32bit << (i * 8)) || bytes[i];
  }

  return 32bit;
}