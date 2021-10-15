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
  /* minimum length check */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (len < minlength ) {
    fprintf(stderr, "Packet discard: Fail to meet the minimum length!");
    return;
  }
  /* tell if the packet is ip or arp */
  uint16_t ethtype = ethertype(packet);
  if (ethtype == ethertype_arp) {
    sr_handle_arp_packet(sr, packet, len, interface);
  } else if (ethtype == ethertype_ip) {
    sr_handle_ip_packet(sr, packet, len, interface);
  } else {
    fprintf(stderr, "Packet discard: Invalid packet type!");
  }
}/* end sr_ForwardPacket */

/*
* ARP packet
*
*/
void sr_handle_arp_packet(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface)
{
  /* arp minimum length check */
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
    fprintf(stderr, "Packet discard: Fail to meet the minimum length!");
    return;
  }

  /* get incoming arp header */
  sr_arp_hdr_t *arp_hdr =  (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  /* get incoming ethernet header */
  sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)packet;
  print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));

  /* tell if the target of the packet is among the router's address
  * tell if it's arp request or reply
  * arp request: reply and send it back
  * arp reply: cache, go through request queue, send outstanding packets
  */
  
  /* Get the interface and tell if tell if it exist */
  struct sr_if* sr_arp_if = (struct sr_if*) sr_get_interface(sr, interface);
  if (sr_arp_if) {
    unsigned short arp_op = ntohs(arp_hdr->ar_op);
    if (arp_op == arp_op_request) {
      /* arp request */
      printf("ARP request\n");

      /* allocate memory for arp reply */
      unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
      uint8_t *arp_reply = malloc(reply_len);

      /* construct ethernet header */
      sr_ethernet_hdr_t *ether_arp_reply_hdr = (sr_ethernet_hdr_t *)arp_reply;
      construct_ether_hdr(ether_hdr, ether_arp_reply_hdr, sr_arp_if, ethertype_arp);

      /* construct arp reply header */
      sr_arp_hdr_t *arp_reply_hdr = (sr_arp_hdr_t *)(arp_reply + sizeof(sr_ethernet_hdr_t));
      arp_reply_hdr->ar_hrd = arp_hdr->ar_hrd;
      arp_reply_hdr->ar_pro = arp_hdr->ar_pro; 
      arp_reply_hdr->ar_hln = arp_hdr->ar_hln; 
      arp_reply_hdr->ar_pln = arp_hdr->ar_pln; 
      arp_reply_hdr->ar_op = htons(arp_op_reply);
      arp_reply_hdr->ar_sip = sr_arp_if->ip;
      arp_reply_hdr->ar_tip = arp_hdr->ar_sip;
      memcpy(arp_reply_hdr->ar_sha, sr_arp_if->addr, ETHER_ADDR_LEN); 
      memcpy(arp_reply_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN); 

      /* send arp reply back*/
      sr_send_packet(sr, arp_reply, reply_len, sr_arp_if->name);
      return;
    } else if (arp_op == arp_op_reply) {
      /* arp reply */
      printf("ARP reply\n");
      /* cache it and go through request queue */
      struct sr_arpreq *req_queue = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
      /* check outstanding packets existence*/
      if (req_queue) {
        struct sr_packet *out_packets = req_queue->packets;
        while (out_packets) {
          struct sr_if *out_inf = sr_get_interface(sr, out_packets->iface);
          /* check if interface exist*/
          if (out_inf) {
            /* send outstanding packets*/
            sr_ethernet_hdr_t *out_ether_hdr = (sr_ethernet_hdr_t *) out_packets->buf;
            memcpy(out_ether_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            memcpy(out_ether_hdr->ether_shost, out_inf->addr, ETHER_ADDR_LEN);
            sr_send_packet(sr, out_packets->buf, out_packets->len, out_packets->iface);
          }
          out_packets = out_packets->next;
        }
        sr_arpreq_destroy(&(sr->cache), req_queue);
      }
      return;
    } else {
      /* type error */
      fprintf(stderr, "Packet discard: Invalid packet type");
      return;
    }
  } else {
    /* error */
      fprintf(stderr, "Packet discard: Invalid interface");
  }
}


/*
*
* IP packet
*
*/
void sr_handle_ip_packet(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface)
{
  /* ip minimum length check */
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    fprintf(stderr, "Packet discard: Fail to meet the minimum length!");
    return;
  }

  /* ip header construct */
  sr_ip_hdr_t *ip_hdr =  (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* checksum */
  uint16_t old_cksum;
  old_cksum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0; /* to calculate the checksum, the checksum filed should be zeroed out first */
  if (old_cksum != cksum(ip_hdr, sizeof(sr_ip_hdr_t))) {
    fprintf(stderr, "Packet discard: Checksum failed");
    return;
  }

  /* get the router interface */
  struct sr_if* sr_rt_if = (struct sr_if*) sr_get_interface(sr, interface);
  /* get the destination interface */
  struct sr_if* sr_dst_if = (struct sr_if*) sr_get_dst_inf(sr, ip_hdr->ip_dst);
  if (sr_dst_if) {
    /* if the ip packet is destined towards the router interfaces */
    if (ip_hdr->ip_p == ip_protocol_icmp) {
      /* ICMP echo request */
      printf("ICMP messege\n");
      /* icmp minimum length check */
      if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t))
        {
            fprintf(stderr, "Packet discard: Fail to meet the minimum length!");
            return;
        }
      sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      /* 8 for echo request */
      if (icmp_hdr->icmp_type == (uint8_t) 8) {
        printf("ICMP echo request\n");
        /* construct icmp echo reply and forward the ip*/
        handle_icmp_message(0, 0, sr, packet, sr_rt_if, ip_hdr, len);
      }
    } else {
      printf("TCP/UDP messege\n");
      /* construct icmp echo reply and forward the ip*/
      handle_icmp_message(3, 3, sr, packet, sr_rt_if, ip_hdr, len);
    }
  } else {
    /* if the ip packet is NOT destined towards the router interfaces*/
    sr_ethernet_hdr_t * ether_hdr = (sr_ethernet_hdr_t *)packet;
    forward_ip(ip_hdr, sr, packet, len, sr_rt_if, ether_hdr);
  }
}

/* helper function: all ICMP messages sender */
void handle_icmp_message(uint8_t icmp_type, uint8_t icmp_code, struct sr_instance *sr, uint8_t *packet, struct sr_if *inf, sr_ip_hdr_t *ip_hdr, unsigned int len) {
  /* first, classification by type */
  uint8_t *icmp_pkt;
  unsigned int icmp_pkt_len;
  if (icmp_type == 0) {
    /* icmp echo */
    icmp_pkt_len = len;
  } else {
    icmp_pkt_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  }
  /* allocate memory for icmp packet */
  icmp_pkt = (uint8_t *)malloc(icmp_pkt_len);
  memcpy(icmp_pkt, packet, icmp_pkt_len);
  /* construct ethernet header */
  sr_ethernet_hdr_t * ether_hdr = (sr_ethernet_hdr_t *)icmp_pkt;
  construct_ether_hdr(ether_hdr, ether_hdr, inf, ethertype_ip);
  /* new ip header */
  sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(icmp_pkt + sizeof(sr_ethernet_hdr_t));

  /* construct ip header */
  if ((icmp_type == 3 && icmp_code == 3) || (icmp_type == 0 && icmp_code == 0)) {
    /* icmp echo reply / port unreachable, source is the destination of the incoming ip */
    new_ip_hdr->ip_src = ip_hdr->ip_dst;
  } else {
    /* otherwise, source should be the ip from the router interface */
    new_ip_hdr->ip_src = inf->ip;
  }
  if (icmp_type == 3) {
    new_ip_hdr->ip_len = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  }
  new_ip_hdr->ip_dst = ip_hdr->ip_src;
  new_ip_hdr->ip_p = ip_protocol_icmp;
  new_ip_hdr->ip_sum = 0;
  new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
  new_ip_hdr->ip_ttl = 64;

  /* construct icmp header */
  if (icmp_type == 0 && icmp_code == 0) {
    /* icmp echo reply (type0) */
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *) (icmp_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_code = icmp_code;
    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
  } else {
    /* icmp messege (type3) */
    sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t *) (icmp_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    /* Internet Header + 64 bits of Data Datagram */
    memcpy(icmp_t3_hdr->data, packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
    memcpy(icmp_t3_hdr->data + sizeof(sr_ip_hdr_t), packet + sizeof(sr_ethernet_hdr_t), 8);
    icmp_t3_hdr->icmp_code = icmp_code;
    icmp_t3_hdr->icmp_type = icmp_type;
    icmp_t3_hdr->icmp_sum = 0;
    icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
    icmp_t3_hdr->next_mtu = 0;
    icmp_t3_hdr->unused = 0;
  }
  /* forward icmp messege */
  print_hdr_ip((uint8_t*)new_ip_hdr);
  print_hdr_icmp((uint8_t*) (sr_icmp_hdr_t *) (icmp_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
  forward_ip(new_ip_hdr, sr, icmp_pkt, icmp_pkt_len, inf, ether_hdr);
  free(icmp_pkt);
}

/* helper function: forwarding ip that is not towards the router's interfaces */
void forward_ip(sr_ip_hdr_t *ip_hdr, struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if* sr_rt_inf, sr_ethernet_hdr_t *ether_hdr) {
  /* ttl check */
  if (ip_hdr->ip_ttl <= 1) {
    printf("ICMP time exceeded!\n");
    /* send icmp time exceeded messege */
    handle_icmp_message(11, 0, sr, packet, sr_rt_inf, ip_hdr, len);
  }
  /* decrement ttl */
  ip_hdr->ip_ttl--;
  /* checksum */
  ip_hdr->ip_sum = 0; /* to calculate the checksum, the checksum filed should be zeroed out first */
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
  /* check routing table and perform LPM*/

  /* get addr in routing table */
  struct sr_rt* curr_rt = sr->routing_table; 
  /* check longest prefix match */
  struct sr_rt* lpm_match_rt;
  /* if the prefix matches the destination's, it's a match */
  while (curr_rt) {
    if ((ip_hdr->ip_dst & curr_rt->mask.s_addr) == (curr_rt->dest.s_addr & curr_rt->mask.s_addr)) {
      if (len < curr_rt->mask.s_addr) {
        len = curr_rt->mask.s_addr;
        lpm_match_rt = curr_rt;
      }
    }
    curr_rt = curr_rt->next;
  }
  /* if match, check arp cache*/
  if (lpm_match_rt) {
    printf("LPM match\n");
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, lpm_match_rt->gw.s_addr);
    if (arp_entry != NULL) {
      printf("ARP cache hit\n");
      /* if hit, change ethernet src/dst, send packet */
      memcpy(ether_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
      memcpy(ether_hdr->ether_shost, sr_rt_inf->addr, ETHER_ADDR_LEN);
      sr_send_packet(sr, packet, len, sr_rt_inf->name);
      printf("Send frame to next hop\n");
      free(arp_entry);
    } else {
      /* else, send arp request(handle_arprequest)*/
      printf("ARP cache miss, resend\n");
      struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, sr_rt_inf->name);
      handle_arpreq(req, sr);
    }
  } else {
    /* else, send icmp net unreachable(type3 code0)*/
    printf("ICMP net unreachable!");
    handle_icmp_message(3, 0, sr, packet, sr_rt_inf, ip_hdr, len);
  }
}

/* helper function: construct ethernet header */
void construct_ether_hdr(sr_ethernet_hdr_t *old_ether_hdr, sr_ethernet_hdr_t *new_ether_hdr, struct sr_if *inf, enum sr_ethertype type) {
  memcpy(new_ether_hdr->ether_dhost, old_ether_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(new_ether_hdr->ether_shost, inf->addr, ETHER_ADDR_LEN);
  new_ether_hdr->ether_type = htons(type);
}

/* helper function: get destination ip interface */
struct sr_if *sr_get_dst_inf(struct sr_instance *sr, uint32_t ip_dst) {
   struct sr_if *if_list = sr->if_list;
   while(if_list) {
     if (if_list->ip == ip_dst) {
       return if_list;
     }
     if_list = if_list->next;
   }
   return NULL;
}

