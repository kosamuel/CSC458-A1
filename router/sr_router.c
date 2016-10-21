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

/* Added this line */
#include <string.h>
#include <stdlib.h>

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

/* Converts a uint8_t array into a uint32_t. */
uint32_t bit_size_conversion(uint8_t bytes[4]) {
  uint32_t thirty_two = bytes[0] | (bytes[1] << 8) |
                 (bytes[2] << 16) | (bytes[3] << 24);

  return thirty_two;
}

uint16_t bit_size_conversion16(uint8_t bytes[2]) {
  uint32_t sixteen = bytes[0] | (bytes[1] << 8);

  return sixteen;
}

void handle_arppacket(struct sr_instance* sr,
                      uint8_t * packet, 
                      unsigned int len,
                      char* interface) {
  /* Copy source information. */
  unsigned char mac[ETHER_ADDR_LEN];
    
  memcpy(mac, (unsigned char *) &packet[22], ETHER_ADDR_LEN);
  uint8_t packet_ip[4];
  memcpy(packet_ip, (uint8_t *)&packet[28], 4);
  uint32_t ip = bit_size_conversion(packet_ip);

  /* The packet is an arp request. */
  if (packet[21] == 0x01) {
    /* Check if the request is for this router. */
    /* Leave blank for now, the interface should handle it. */
	
      /* Add source address to arp cache. */
      sr_arpcache_insert(&sr->cache, mac, ip);

      /* 
      Set the Opcode to reply
      Swap the destination and source addresses
      replace the source address
      */
      uint8_t packet_copy[len];
      memcpy(packet_copy, packet, len);

      /* Ethernet Information. */
      uint8_t src_ether[ETHER_ADDR_LEN];

      /* ARP packet information. */
      uint8_t src_hdw[ETHER_ADDR_LEN];
      uint8_t src_pcl[4];
      uint8_t des_hdw[ETHER_ADDR_LEN];
      unsigned char * iface_addr = sr_get_interface(sr, interface)->addr;
      memcpy(des_hdw, &iface_addr, ETHER_ADDR_LEN);
      uint8_t des_pcl[4];

      /* Save the destination and source address information. */
      memcpy(src_ether, &packet[6], ETHER_ADDR_LEN);

      memcpy(src_hdw, &packet[22], ETHER_ADDR_LEN);
      memcpy(src_pcl, &packet[28], 4);
      memcpy(des_pcl, &packet[38], 4);

      /* Write to the packet copy. */
      packet_copy[21] = 0x02;
      memcpy(&packet_copy[0], src_ether, ETHER_ADDR_LEN);
      memcpy(&packet_copy[6], iface_addr, ETHER_ADDR_LEN);
      memcpy(&packet_copy[22], iface_addr, ETHER_ADDR_LEN);
      memcpy(&packet_copy[28], des_pcl, 4);
      memcpy(&packet_copy[32], src_hdw, ETHER_ADDR_LEN);
      memcpy(&packet_copy[38], src_pcl, 4);

      /* Send the ARP reply. */
      sr_send_packet(sr, packet_copy, sizeof(packet_copy), interface);

    /* If the request is not for this router, destroy it. */

  /* The packet is an arp reply. */
  } else if (packet[21] == 0x02) {
    /* Cache reply. */
    struct sr_arpreq *requests = sr_arpcache_insert(&sr->cache, mac, ip);
    
    /* 
    Go through request queue and send queued packets
    for this arp.
    */
    struct sr_packet *rpacket;
    if (requests != NULL) {
      for(rpacket = requests->packets; rpacket != NULL; rpacket = rpacket->next) {
        /* Fill out Ether header. */
        struct sr_if* this_mac = sr_get_interface(sr, rpacket->iface);
        memcpy(rpacket->buf, mac, 6);
        memcpy(&rpacket->buf[6], this_mac->addr, 6);

        /* Update checksum and TTL. */
	uint8_t ip_len8[2];
        memcpy(ip_len8, &rpacket->buf[16], 2);
        int ip_len = htons(bit_size_conversion(ip_len8));

        rpacket->buf[22] = rpacket->buf[22] - 1;

        rpacket->buf[24] = 0x00;
        rpacket->buf[25] = 0x00;

        uint16_t new_checksum = htons(cksum(&rpacket->buf[14], ip_len));
        uint8_t new_checksum0 = new_checksum >> 8;
        uint8_t new_checksum1 = (new_checksum << 8) >> 8;
        rpacket->buf[24] = new_checksum0;
        rpacket->buf[25] = new_checksum1;
	printf("new_checksum: %d\n", new_checksum);
        printf("new_checksum in packet: %d.%d\n", rpacket->buf[24], rpacket->buf[25]);

        sr_send_packet(sr, rpacket->buf, rpacket->len, rpacket->iface);

      }
    }

    /* Remove the request queue. */
    sr_arpreq_destroy(&sr->cache, requests);

  }
}

void handle_ippacket(struct sr_instance* sr,
                      uint8_t * packet, 
                      unsigned int len,
                      char* interface) {

  /* Perform checksum. */
  uint8_t packet_copy[len];
  memcpy(packet_copy, packet, len);
	
  uint8_t len_in_packet[2];
  memcpy(len_in_packet, &packet[16], 2);
  int ip_len = htons(bit_size_conversion(len_in_packet));
  printf("len_in_packet: %d.%d\n", len_in_packet[0], len_in_packet[1]);
  printf("ip_len: %d\n", ip_len);
  printf("True ip_len: %d%d\n", packet[16], packet[17]);
  
  uint8_t cksum_buf[2];
  memcpy(cksum_buf, &packet[24], 2);
  uint16_t this_cksum = htons(bit_size_conversion16(cksum_buf));
  printf("cksum: %d\n", this_cksum);
  printf("True cksum: %d%d\n", packet[24], packet[25]);
  
  packet_copy[24] = 0x00;
  packet_copy[25] = 0x00;

  uint16_t ip_checksum = htons(cksum(&packet_copy[14], ip_len));
  printf("Checksum checking: %d\n", ip_checksum);

  if (ip_checksum != this_cksum) {
    printf("Incorrect checksum line 173");
    return;

  /* Check for correct length. */
  } else if (ip_len != len - 14) {
    printf("Incorrect length line 177");
    return;

  } else if (packet_copy[22] == 0) {
    printf("TTL is 0");
    return;  

  }

  printf("Correct Checksum\n");

  /* Get destination IP address for this packet. */
  uint8_t des_addr[4];
  memcpy(des_addr, &packet[30], 4);
  uint32_t des_addr32 = bit_size_conversion(des_addr);

  uint32_t this_ip = sr_get_interface(sr, interface)->ip;

  /* If the packet is for this router. */
  if (memcmp(&des_addr32, &this_ip, 4) == 0) {
    printf("Successfully compared addresses: Line 164\n");
    /* If it is an ICMP echo request. */

  } else {
    /* Check routing table. */
    struct sr_rt *rtable;
    char ip_string[9];

    sprintf(ip_string, "%d.%d.%d.%d", des_addr[0], des_addr[1],
                                      des_addr[2], des_addr[3]);

    /* IP address information. */
    /*
    uint8_t packet_ip[4];
    memcpy(packet_ip, (uint8_t *)&packet[28], 4);
    uint32_t ip = bit_size_conversion(packet_ip);*/

    int len_longest_prefix = 0;
    char *longest_prefix = malloc(sizeof(char) * 1024);
    strncpy(longest_prefix, "None", 5);
    struct sr_rt *outgoing;

    /* For each routing table entry. */
    for (rtable = sr->routing_table; rtable != NULL; rtable = rtable->next) {
      printf("Prefix %s\n", inet_ntoa(rtable->dest));
      printf("Destination IP %s\n", ip_string);
      
      if (sizeof(inet_ntoa(rtable->dest)) > len_longest_prefix &&
         strncmp(inet_ntoa(rtable->dest), ip_string, sizeof(ip_string) - 1) == 0) {
         
         strncpy(longest_prefix, inet_ntoa(rtable->dest), sizeof(inet_ntoa(rtable->dest)));
         len_longest_prefix = sizeof(inet_ntoa(rtable->dest));
         outgoing = rtable;
     
      }
    }

      /* Check longest prefix match with the IP address above. */
      if (strncmp(longest_prefix, "None", 5) != 0) {
        struct sr_arpentry *arpentry = sr_arpcache_lookup(&sr->cache, des_addr32);	

        /* If the arp was a miss. */
        if (arpentry == NULL) {
          printf("xxxxxxxxxxxxxxxxxxxxxxxxQueuing request: Line 187\n");
          sr_arpcache_queuereq(&sr->cache, des_addr32, packet_copy, len, outgoing->interface);
          printf("Finished queuing request: Line 189\n");

        } else {
          printf("***************Redirecting packet: Line 192\n");

          /* Update ethernet header before sending. */
          struct sr_arpentry* destination = sr_arpcache_lookup(&sr->cache, des_addr32);
          struct sr_if* this_mac = sr_get_interface(sr, outgoing->interface);
          memcpy(packet_copy, destination->mac, 6);
          memcpy(&packet_copy[6], this_mac->addr, 6);

          /* Update checksum and TTL. */
          printf("TTL before: %d\n", packet_copy[22]);
          packet_copy[22] = packet_copy[22] - 1;
          printf("TTL after: %d\n", packet_copy[22]);

          /* Reset the checksum. */
          packet_copy[24] = 0x00;
	        packet_copy[25] = 0x00;

          uint16_t new_checksum = htons(cksum(&packet_copy[14], ip_len));
          uint8_t new_checksum0 = new_checksum >> 8;
          uint8_t new_checksum1 = (new_checksum << 8) >> 8;
          packet_copy[24] = new_checksum0;
          packet_copy[25] = new_checksum1;
          /* memcpy(&packet_copy[24], (uint8_t *)new_checksum, 2); */
          printf("cksum in packet: %d%d\n", packet_copy[24], packet_copy[25]);
          printf("Reverse cksum: %d\n", new_checksum);

          sr_send_packet(sr, packet_copy, len, outgoing->interface);
          printf("Finished redirecting packet: Line 194\n");

        }
      
      /* There were no matches. */
      } else {
        /* Get IP information. */
        uint8_t src_addr_copy[4];
        memcpy(src_addr_copy, &packet[26], 4);
        uint32_t des_addr = bit_size_conversion(src_addr_copy);
        struct sr_arpentry* destination = sr_arpcache_lookup(&sr->cache, des_addr);

        /* Make the ICMP header. */
        uint8_t packet_copy2[len];
        memcpy(packet_copy2, packet, len);
        uint8_t icmp_hdr = icmp_t3(&packet_copy2[14], 0x03, 0x00);

        /* Make the Ethernet Header. */
        struct sr_if * return_iface = sr_get_interface(sr, interface);
        struct sr_ethernet_hdr ether;
        
        memcpy(ether.ether_dhost, destination->mac, ETHER_ADDR_LEN);
        memcpy(ether.ether_shost, return_iface->addr, ETHER_ADDR_LEN);
        ether.ether_type = htons(0x0800);

        /* Update IP information. */
        memcpy(&packet_copy2[26], return_iface->ip, 4);
        memcpy(&packet_copy2[30], destination->ip, 4);

        /* Make the packet. */
        uint8_t buf[sizeof(ether) + sizeof(&packet_copy2[14]) + sizeof(icmp_hdr)];
        memcpy(buf, &ether, sizeof(ether));
        memcpy(&buf[sizeof(ether)], &packet_copy2[14], sizeof(&packet_copy2[14]));
        memcpy(&buf[sizeof(ether) + sizeof(&packet_copy2[14])], icmp_hdr, sizeof(icmp_hdr));

        sr_send_packet(sr, buf, sizeof(&buf), return_iface->name);

      }
    free(longest_prefix);  

  }  
}

/* If the packet is not for this router. */

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
    handle_arppacket(sr, packet, len, interface);

  /* The received packet is an IP packet. */  
  } else if (packet[12] == 0x08 && packet[13] == 0x00) {
    handle_ippacket(sr, packet, len, interface);

  }

}/* end sr_ForwardPacket */


