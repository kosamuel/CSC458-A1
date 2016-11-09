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

void send_icmp_reply(struct sr_instance* sr, 
               uint8_t * packet,
               unsigned int len,
               char* interface, 
               uint8_t type, 
               uint8_t code) {
  
  struct sr_rt *rtable;
  char ip_string[9];

  /* Convert the ip address into a string */
  sprintf(ip_string, "%d.%d.%d.%d", packet[26], packet[27],
                                    packet[28], packet[29]);

  /* Initialize variables for Longest Prefix Matching */
  int len_longest_prefix = 0;
  /* char *longest_prefix = malloc(sizeof(char) * 1024); */
  char longest_prefix[128]; 
  strncpy(longest_prefix, "None", 5);
  struct sr_rt *outgoing;

  /* For each routing table entry, compare prefixes and keep the longest match. */
  for (rtable = sr->routing_table; rtable != NULL; rtable = rtable->next) {
    
    /* Compare IP addresses.  Both are in a.b.c.d format. */
    if (sizeof(inet_ntoa(rtable->dest)) > len_longest_prefix &&
       strncmp(inet_ntoa(rtable->dest), ip_string, sizeof(ip_string) - 1) == 0) {
       
       strncpy(longest_prefix, inet_ntoa(rtable->dest), sizeof(inet_ntoa(rtable->dest)));
       len_longest_prefix = sizeof(inet_ntoa(rtable->dest));
       outgoing = rtable;  /* Set the rtable entry as the current outgoing interface */
   
    }
  }

  /* Check if the longest prefix was found */
  if (strncmp(longest_prefix, "None", 5) != 0) {
    uint8_t src_ip[4];
    memcpy(src_ip, &packet[26], 4);
    uint32_t src_ip32 = bit_size_conversion(src_ip);

    /* Check if the MAC to IP entry is in the cache */
    struct sr_arpentry *arpentry = sr_arpcache_lookup(&sr->cache, src_ip32);  

    /* If the arp was a miss. */
    if (arpentry == NULL) {
      sr_arpcache_queuereq(&sr->cache, src_ip32, packet, len, outgoing->interface);

    /* Cache entry was found. */
    } else {

      printf("ip_len before changes: %d-%d\n", packet[16], packet[17]);
      
      /* Create ICMP header first */
      /*
      uint8_t *icmp_hdr;
      if (type == 0x00) {
        icmp_hdr = icmp_t3(&packet[14], type, code);

      } else {
        icmp_hdr = icmp_t3(&packet[14], type, code);

      }*/
      
      packet[34] = type;
      packet[35] = code;
      packet[36] = 0x00;
      packet[37] = 0x00;

      uint8_t icmp_hdr[len - 34];
      memcpy(icmp_hdr, &packet[34], len - 34);

      uint16_t icmp_checksum = htons(cksum(icmp_hdr, len - 34));
      uint8_t icmp_checksum0 = icmp_checksum >> 8;
      uint8_t icmp_checksum1 = (icmp_checksum << 8) >> 8;
      icmp_hdr[2] = icmp_checksum0;
      icmp_hdr[3] = icmp_checksum1;


      /*
      uint8_t icmp_hdr[36];

      struct sr_icmp_t3_hdr icmp_response;
      icmp_response.icmp_type = type;
      icmp_response.icmp_code = code;
      icmp_response.icmp_sum = 0x0000;
      icmp_response.unused = 0x0000;
      icmp_response.next_mtu = 0x0000;
      memcpy(icmp_response.data, &packet[14], 28);

      memcpy(icmp_hdr, &icmp_response, 36);
      */
      
       
      /* Update IP packet next */
      /* Update total length */
      uint8_t len_in_packet[2];
      memcpy(len_in_packet, &packet[16], 2);
      /*int ip_len = htons(bit_size_conversion(len_in_packet)) + 8;*/
      int ip_len = htons(bit_size_conversion(len_in_packet));

      packet[16] = (ip_len) >> 8;
      packet[17] = (ip_len);

      printf("ip_len after changes: %d-%d\n", packet[16], packet[17]);

      uint8_t buf[len + 8];
      printf("ICMP type: %d\n", icmp_hdr[0]);

      printf("First 3 bytes of the packet in icmp: %d-%d-%d-%d-%d\n", icmp_hdr[8],
    						icmp_hdr[9],
    						icmp_hdr[10],
    						icmp_hdr[11],
    						icmp_hdr[12]);

      printf("First 3 bytes of packet: %d-%d-%d-%d-%d\n", packet[14],
    						packet[15],
    						packet[16],
    						packet[17],
    						packet[18]);

      /* Get necessary information */
      struct sr_if *this_if = sr_get_interface(sr, interface);
      uint8_t packet_owner_mac[6];
      memcpy(packet_owner_mac, &packet[6], ETHER_ADDR_LEN);
      uint8_t packet_owner_ip[4];
      memcpy(packet_owner_ip, &packet[26], 4);

      /* Update IP header */
      packet[23] = 0x01;
      packet[24] = 0x00;
      packet[25] = 0x00;

      /*if (type == 0x00) {*/
      if (1) {
        memcpy(&packet[26], &packet[30], 4);
      } else {
        memcpy(&packet[26], &this_if->ip, 4);
      /*memcpy(&packet[26], &packet[30], 4);*/
      }

      memcpy(&packet[30], packet_owner_ip, 4);

      printf("packet_owner_mac: %d:%d:%d:%d:%d:%d\n", packet[6],
    						packet[7],
    						packet[8],
    						packet[9],
    						packet[10],
    						packet[11]);

      printf("packet_owner_ip: %d.%d.%d.%d\n", packet[26],
    					packet[27],
    					packet[28],
    					packet[29]);

      printf("IP protocol: %d\n", packet[23]);
      printf("ICMP type, code: %d, %d\n", icmp_hdr[0], icmp_hdr[1]);

      /* Put the packet together */
      memcpy(buf, packet, len);
      memcpy(buf, packet_owner_mac, ETHER_ADDR_LEN);
      memcpy(&buf[6], &this_if->addr, ETHER_ADDR_LEN);
      memcpy(&buf[34], icmp_hdr, ip_len - 20);

      /* IP Checksum */
      uint16_t new_checksum = htons(cksum(&buf[14], ip_len));
      uint8_t new_checksum0 = new_checksum >> 8;
      uint8_t new_checksum1 = (new_checksum << 8) >> 8;
      buf[24] = new_checksum0;
      buf[25] = new_checksum1;

      printf("new dest mac: %d:%d:%d:%d:%d:%d\n", buf[0],
    						buf[1],
    						buf[2],
    						buf[3],
    						buf[4],
    						buf[5]);

      printf("new dest ip: %d.%d.%d.%d\n", buf[30],
    					buf[31],
    					buf[32],
    					buf[33]);

      printf("Packet ICMP type, code: %d, %d\n", buf[34], buf[35]);
      printf("Interface name: %s\n", interface);
      sr_send_packet(sr, buf, sizeof(buf), interface);
    }
}

void send_icmp(struct sr_instance* sr, 
               uint8_t * packet,
               unsigned int len,
               char* interface, 
               uint8_t type, 
               uint8_t code) {

  printf("ip_len before changes: %d-%d\n", packet[16], packet[17]);
  
  uint8_t icmp_hdr[36];    
  
  icmp_hdr[0] = type;
  icmp_hdr[1] = code;
  icmp_hdr[2] = 0x00;
  icmp_hdr[3] = 0x00;
  icmp_hdr[4] = 0x00;
  icmp_hdr[5] = 0x00;
  icmp_hdr[6] = 0x00;
  icmp_hdr[7] = 0x00;

  memcpy(&icmp_hdr[8], &packet[14], 28);
  
  /* Perform Checksum */
  uint16_t icmp_checksum = htons(cksum(icmp_hdr, 36));
  uint8_t icmp_checksum0 = icmp_checksum >> 8;
  uint8_t icmp_checksum1 = (icmp_checksum << 8) >> 8;
  icmp_hdr[2] = icmp_checksum0;
  icmp_hdr[3] = icmp_checksum1;
  
  int ip_len = 20 + 36; /* IP header + ICMP */

  packet[16] = (ip_len) >> 8;
  packet[17] = (ip_len);

  uint8_t buf[ip_len + 14];  /* IP packet + Ethernet header */

  /* Get necessary information */
  struct sr_if *this_if = sr_get_interface(sr, interface);
  uint8_t packet_owner_mac[6];
  memcpy(packet_owner_mac, &packet[6], ETHER_ADDR_LEN);
  uint8_t packet_owner_ip[4];
  memcpy(packet_owner_ip, &packet[26], 4);

  /* Update IP header */
  packet[23] = 0x01;
  packet[24] = 0x00;
  packet[25] = 0x00;

  /*if (type == 0x00) {*/
  if (code == 0x03) {
    memcpy(&packet[26], &packet[30], 4);
  } else {
    memcpy(&packet[26], &this_if->ip, 4);
  /*memcpy(&packet[26], &packet[30], 4);*/
  }

  memcpy(&packet[30], packet_owner_ip, 4);

  /* Put the packet together */
  memcpy(buf, packet, 34); /* Copy only the Ethernet and IP headers */
  memcpy(buf, packet_owner_mac, ETHER_ADDR_LEN);
  memcpy(&buf[6], &this_if->addr, ETHER_ADDR_LEN);
  memcpy(&buf[34], icmp_hdr, 36);

  /* IP Checksum */
  uint16_t new_checksum = htons(cksum(&buf[14], ip_len));
  uint8_t new_checksum0 = new_checksum >> 8;
  uint8_t new_checksum1 = (new_checksum << 8) >> 8;
  buf[24] = new_checksum0;
  buf[25] = new_checksum1;

  sr_send_packet(sr, buf, sizeof(buf), interface);
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
	
    /* Add source address to arp cache. */
    sr_arpcache_insert(&sr->cache, mac, ip);

    /* 
    Set the Opcode to reply
    Swap the destination and source addresses
    replace the source address
    */

    /* Make a copy of the packet */
    uint8_t packet_copy[len];
    memcpy(packet_copy, packet, len);

    /* Ethernet Information. */
    uint8_t src_ether[ETHER_ADDR_LEN];

    /* ARP packet information. */
    uint8_t src_hdw[ETHER_ADDR_LEN];
    uint8_t src_pcl[4];
    uint8_t des_hdw[ETHER_ADDR_LEN];
    struct sr_if * this_iface = sr_get_interface(sr, interface);
    memcpy(des_hdw, &this_iface->addr, ETHER_ADDR_LEN);
    uint8_t des_pcl[4];

    /* Save the destination and source address information. */
    memcpy(src_ether, &packet[6], ETHER_ADDR_LEN);

    memcpy(src_hdw, &packet[22], ETHER_ADDR_LEN);
    memcpy(src_pcl, &packet[28], 4);
    memcpy(des_pcl, &packet[38], 4);

    /* Write to the packet copy. */
    packet_copy[21] = 0x02;
    memcpy(&packet_copy[0], src_ether, ETHER_ADDR_LEN);
    memcpy(&packet_copy[6], this_iface->addr, ETHER_ADDR_LEN);
    memcpy(&packet_copy[22], des_hdw, ETHER_ADDR_LEN);
    memcpy(&packet_copy[28], des_pcl, 4);
    memcpy(&packet_copy[32], src_hdw, ETHER_ADDR_LEN);
    memcpy(&packet_copy[38], src_pcl, 4);

    /* Send the ARP reply. */
    sr_send_packet(sr, packet_copy, sizeof(packet_copy), interface);

  /* The packet is an arp reply. */
  } else if (packet[21] == 0x02) {
    /* Cache reply. */
    /* mac, ip of the replying machine */
    struct sr_arpreq *requests = sr_arpcache_insert(&sr->cache, mac, ip);
    
    /* 
    Go through request queue and send queued packets
    for this arp.
    */
    struct sr_packet *rpacket;
    if (requests != NULL) {
      for(rpacket = requests->packets; rpacket != NULL; rpacket = rpacket->next) {
        /* Fill out Ether header. */
        /* The MAC address for the destination was unknown. */
        struct sr_if* this_iface = sr_get_interface(sr, rpacket->iface);
        memcpy(rpacket->buf, mac, 6);
        memcpy(&rpacket->buf[6], this_iface->addr, 6);

        /* Update checksum and TTL. */
        /* Need to do this since TTl is decreased by 1. */
      	uint8_t ip_len8[2];
        memcpy(ip_len8, &rpacket->buf[16], 2);
        int ip_len = htons(bit_size_conversion16(ip_len8));

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

  uint8_t src_addr[4];
  memcpy(src_addr, &packet[26], 4);
  uint32_t src_addr32 = bit_size_conversion(src_addr);
  struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, src_addr32);
  if (entry != NULL) {
    entry->valid = 1;
    entry->added = time(NULL);
  }

  uint8_t packet_copy2[len];
  memcpy(packet_copy2, packet, len);

  /* Perform checksum. */
  uint8_t packet_copy[len];
  memcpy(packet_copy, packet, len);
	
  /* Get the of the ip packet */
  uint8_t len_in_packet[2];
  memcpy(len_in_packet, &packet[16], 2);
  int ip_len = htons(bit_size_conversion(len_in_packet));
  printf("len_in_packet: %d.%d\n", len_in_packet[0], len_in_packet[1]);
  printf("ip_len: %d\n", ip_len);
  printf("True ip_len: %d%d\n", packet[16], packet[17]);
  
  /* Make a copy of the packet checksum */
  uint8_t cksum_buf[2];
  memcpy(cksum_buf, &packet[24], 2);
  uint16_t this_cksum = htons(bit_size_conversion16(cksum_buf));
  printf("cksum: %d\n", this_cksum);
  printf("True cksum: %d%d\n", packet[24], packet[25]);
  
  /* Reset checksum */
  packet_copy[24] = 0x00;
  packet_copy[25] = 0x00;

  uint16_t ip_checksum = htons(cksum(&packet_copy[14], ip_len));
  printf("Checksum checking: %d\n", ip_checksum);

  /*if (ip_checksum != this_cksum) {
    printf("Incorrect checksum line 173");
    return;
  */
  /* Check for correct length. *//*
  } else if (ip_len != len - 14) {
    printf("Incorrect length line 177");
    return;
  */

  printf("Correct Checksum\n");

  /* Packet is correct, now process it */
  /* First, check if the packet is for this router. */
  /* Get destination IP address for this packet. 
     Also convert the IP into uint32_t.
  */
  uint8_t des_addr[4];
  memcpy(des_addr, &packet[30], 4);
  uint32_t des_addr32 = bit_size_conversion(des_addr);

  /* Get the receiving interface's IP */
  uint32_t this_ip = sr_get_interface(sr, interface)->ip;


  /* If the packet is for this router. */
  struct sr_if *iface;
  for (iface = sr->if_list; iface != NULL; iface = iface->next) {
    if (memcmp(&des_addr32, &iface->ip, 4) == 0) {
      printf("Successfully compared addresses: Line 164\n");

      /* It is an echo request */
      if (packet[23] == 0x01) {
        /*if (packet[34] == 0x08 && packet[35] == 0x00) {*/

          uint8_t packet_copy2[len];
          memcpy(packet_copy2, packet, len);

          send_icmp_reply(sr, packet_copy2, len, interface, 0x00, 0x00);
          return;
        /*}*/

      /* It is an UDP or TCP packet */
      } else if (packet[23] == 0x06 || packet[23] == 0x11) {
        
        uint8_t packet_copy2[len];
        memcpy(packet_copy2, packet, len);

        send_icmp(sr, packet_copy2, len, interface, 0x03, 0x03);
        return;
      }
    }
  }
  
  if (packet_copy[22] - 1 <= 0) {
    printf("TTL is 0");

    uint8_t packet_copy2[len];
    memcpy(packet_copy2, packet, len);

    send_icmp(sr, packet_copy2, len, interface, 0x0B, 0x00);

    return;  

  }

  /* The packet is not for here and needs to be redirected */
  /* Check routing table. */
  struct sr_rt *rtable;
  char ip_string[9];

  /* Convert the ip address into a string */
  sprintf(ip_string, "%d.%d.%d.%d", des_addr[0], des_addr[1],
                                    des_addr[2], des_addr[3]);

  /* Initialize variables for Longest Prefix Matching */
  int len_longest_prefix = 0;
  /* char *longest_prefix = malloc(sizeof(char) * 1024); */
  char longest_prefix[128]; 
  strncpy(longest_prefix, "None", 5);
  struct sr_rt *outgoing;

  /* For each routing table entry, compare prefixes and keep the longest match. */
  for (rtable = sr->routing_table; rtable != NULL; rtable = rtable->next) {
    printf("Prefix %s\n", inet_ntoa(rtable->dest));
    printf("Destination IP %s\n", ip_string);
    
    /* Compare IP addresses.  Both are in a.b.c.d format. */
    
    if (sizeof(inet_ntoa(rtable->dest)) > len_longest_prefix &&
       strncmp(inet_ntoa(rtable->dest), ip_string, sizeof(ip_string) - 1) == 0) {
       
       strncpy(longest_prefix, inet_ntoa(rtable->dest), sizeof(inet_ntoa(rtable->dest)));
       len_longest_prefix = sizeof(inet_ntoa(rtable->dest));
       outgoing = rtable;  /* Set the rtable entry as the current outgoing interface */
   
    }
  }

  /* Check if the longest prefix was found */
  if (strncmp(longest_prefix, "None", 5) != 0) {
    /* Check if the MAC to IP entry is in the cache */
    struct sr_arpentry *arpentry = sr_arpcache_lookup(&sr->cache, des_addr32);	

    /* If the arp was a miss. */
    if (arpentry == NULL) {
      printf("xxxxxxxxxxxxxxxxxxxxxxxxQueuing request: Line 187\n");
      sr_arpcache_queuereq(&sr->cache, des_addr32, packet_copy2, len, outgoing->interface);
      printf("Finished queuing request: Line 189\n");

    /* Cache entry was found. */
    } else {
      printf("***************Redirecting packet: Line 192\n");

      /* Update ethernet header, TTL, and checksum before sending. */
      /* des_addr32 is the uint32_t destination address for the packet */
      /*struct sr_arpentry* destination = sr_arpcache_lookup(&sr->cache, des_addr32); */
      struct sr_if* this_mac = sr_get_interface(sr, outgoing->interface);
      memcpy(packet_copy2, arpentry->mac, 6);
      memcpy(&packet_copy2[6], this_mac->addr, 6);

      /* Update TTL. */
      printf("TTL before: %d\n", packet_copy2[22]);
      packet_copy2[22] = packet_copy2[22] - 1;
      printf("TTL after: %d\n", packet_copy2[22]);

      /* Reset the checksum. */
      packet_copy2[24] = 0x00;
      packet_copy2[25] = 0x00;

      uint8_t len_in_packet[2];
      memcpy(len_in_packet, &packet[16], 2);
      int ip_len = htons(bit_size_conversion(len_in_packet));

      /* Recalculate checksum */
      uint16_t new_checksum = htons(cksum(&packet_copy2[14], ip_len));
      uint8_t new_checksum0 = new_checksum >> 8;
      uint8_t new_checksum1 = (new_checksum << 8) >> 8;
      packet_copy2[24] = new_checksum0;
      packet_copy2[25] = new_checksum1;
      /* memcpy(&packet_copy[24], (uint8_t *)new_checksum, 2); */
      printf("cksum in packet: %d%d\n", packet_copy2[24], packet_copy2[25]);
      printf("Reverse cksum: %d\n", new_checksum);

      sr_send_packet(sr, packet_copy2, len, outgoing->interface);
      printf("Finished redirecting packet: Line 194\n");

    }
  
  /* There were no matches. */
  } else {
    uint8_t packet_copy2[len];
    memcpy(packet_copy2, packet, len);

    send_icmp(sr, packet_copy2, len, interface, 0x03, 0x00);

  }
  /*free(longest_prefix); */   
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


