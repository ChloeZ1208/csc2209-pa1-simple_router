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
      construct_ether_hdr(ether_hdr, ether_arp_reply_hdr, sr_arp_if);

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
      free(arp_reply);
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
        sr_arpreq_destroy(&sr->cache, req_queue);
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
  /* get incoming ethernet header */
  sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)packet;

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

	/* ttl check */
	if (ip_hdr->ip_ttl <= 1) {
		printf("ICMP time exceeded!\n");
		/* send icmp time exceeded messege */
		uint8_t *icmp_t3_pkt = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
		construct_ether_hdr(ether_hdr, (sr_ethernet_hdr_t *)icmp_t3_pkt, sr_rt_if);
		/* construct ip header */
		sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(icmp_t3_pkt + sizeof(sr_ethernet_hdr_t));
		construct_ip_hdr(new_ip_hdr, ip_hdr, sr_rt_if);
		/* construct icmp header */
		sr_icmp_t3_hdr_t *new_icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(icmp_t3_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		construct_icmp_hdr(11, 0, ip_hdr, new_icmp_t3_hdr);

		/* check arp cache*/
		struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_src);
		if (arp_entry != NULL) {
			printf("ARP cache hit\n");
			/* if hit, change ethernet src/dst, send packet to next frame */
			sr_send_packet(sr, icmp_t3_pkt, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), sr_rt_if->name);
			free(icmp_t3_pkt);
		} else {
			/* no hit, cache it to the queue and send arp request(handle_arprequest)*/
			struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_src, icmp_t3_pkt, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), sr_rt_if->name);
			handle_arpreq(req, sr);
		}
	}

  if (sr_dst_if) {
    /* if the ip packet is destined towards the router interfaces */
    if (ip_hdr->ip_p == ip_protocol_icmp) {
      /* ICMP echo request */
      printf("ICMP messege received\n");
      sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      /* 8 for echo request */
      if (icmp_hdr->icmp_type == (uint8_t) 8) {
        printf("ICMP echo request\n");
        /* construct and forward icmp echo reply */
        /* get addr in routing table */
        struct sr_rt* curr_rt = sr->routing_table; 
        /* check longest prefix match */
        struct sr_rt* lpm_match_rt;
        /* if the prefix of incoming ip matches the routing table, it's a match */
        uint32_t max_len = 0;
        while (curr_rt) {
          if ((ip_hdr->ip_src & curr_rt->mask.s_addr) == (curr_rt->dest.s_addr & curr_rt->mask.s_addr)) {
            if (max_len < curr_rt->mask.s_addr) {
              max_len = curr_rt->mask.s_addr;
              lpm_match_rt = curr_rt;
            }
          }
          curr_rt = curr_rt->next;
        } 
        /* if match, check arp cache*/
        if (lpm_match_rt) {
          printf("LPM match-icmp\n");
          struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, lpm_match_rt->gw.s_addr);
          struct sr_if *lpm_inf = sr_get_interface(sr, lpm_match_rt->interface);
          if (arp_entry != NULL) {
            printf("ARP cache hit\n");
            /* if hit, change ethernet/ip/ src/dst & icmp checksum, send packet to next frame */
            /* construct ethernet header */
            construct_ether_hdr(ether_hdr, ether_hdr, lpm_inf);/* if hit, send it from lpm matched rtable */
            /* construct ip header */
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_ttl = 64;
            uint32_t temp = ip_hdr->ip_src;
            ip_hdr->ip_src = ip_hdr->ip_dst;
            ip_hdr->ip_dst = temp;
            ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
            /* construct icmp header */
            icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_code = 0;
            icmp_hdr->icmp_type = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
            sr_send_packet(sr, packet, len, lpm_inf->name); /* if hit, send it from lpm matched rtable */
          } else {
            /* no hit, cache it to the queue and send arp request(handle_arprequest)*/
            printf("ARP cache miss\n");
            /* construct ethernet header */
            construct_ether_hdr(ether_hdr, ether_hdr, sr_rt_if); /* if not hit, send it from connected interface*/
            /* construct ip header */
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_ttl = 64;
            uint32_t temp = ip_hdr->ip_src;
            ip_hdr->ip_src = ip_hdr->ip_dst;
            ip_hdr->ip_dst = temp;
            ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
            /* construct icmp header */
            icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_code = 0;
            icmp_hdr->icmp_type = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
            struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, lpm_inf->name);
            handle_arpreq(req, sr);
          }
        } else {
            /* TODO: else, send icmp net unreachable(type3 code0)*/
            printf("ICMP net unreachable!");
        }
      } else {
        printf("Not icmp echo request\n");
      }
    } else {
      printf("TCP/UDP messege\n");
      /* construct icmp port unreachable */
      struct sr_rt* curr_rt = sr->routing_table; 
      /* check longest prefix match */
      struct sr_rt* lpm_match_rt;
      /* if the prefix matches the destination's, it's a match */
      uint32_t max_len = 0;
      while (curr_rt) {
        if ((ip_hdr->ip_src & curr_rt->mask.s_addr) == (curr_rt->dest.s_addr & curr_rt->mask.s_addr)) {
          if (max_len < curr_rt->mask.s_addr) {
            max_len = curr_rt->mask.s_addr;
            lpm_match_rt = curr_rt;
          }
        }
        curr_rt = curr_rt->next;
      } 
      if (lpm_match_rt) {
        printf("LPM match-tcp/udp\n");
        /* construct icmp port unreachable */
        uint8_t *icmp_t3_pkt = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        construct_ether_hdr(ether_hdr, (sr_ethernet_hdr_t *)icmp_t3_pkt, sr_dst_if);
        /* construct ip header */
        sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(icmp_t3_pkt + sizeof(sr_ethernet_hdr_t));
        construct_ip_hdr(new_ip_hdr, ip_hdr, sr_dst_if);
        /* construct icmp header */
        sr_icmp_t3_hdr_t *new_icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(icmp_t3_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        construct_icmp_hdr(3, 3, ip_hdr, new_icmp_t3_hdr);

        /* check arp cache */
        struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, lpm_match_rt->gw.s_addr);
        struct sr_if *lpm_inf = sr_get_interface(sr, lpm_match_rt->interface);
        if (arp_entry != NULL) {
          printf("ARP cache hit\n");
          /* if hit, change ethernet src/dst, send packet to next frame */
          sr_send_packet(sr, icmp_t3_pkt, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), lpm_inf->name);
          free(icmp_t3_pkt);
        } else {
          /* no hit, cache it to the queue and send arp request(handle_arprequest)*/
          struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_src, icmp_t3_pkt, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), lpm_inf->name);
          handle_arpreq(req, sr);
        }
      } else {
          /* TODO: else, send icmp net unreachable(type3 code0)*/
          printf("LPM failed!");
      }
    }
    /* if the ip packet is NOT destined towards the router interfaces*/
  } else {
		/* check routing table and perform LPM*/
		/* get addr in routing table */
		struct sr_rt* curr_rt = sr->routing_table; 
		/* check longest prefix match */
		struct sr_rt* lpm_match_rt;
		/* if the prefix matches the destination's, it's a match */
		uint32_t max_len = 0;
		while (curr_rt) {
			if ((ip_hdr->ip_dst & curr_rt->mask.s_addr) == (curr_rt->dest.s_addr & curr_rt->mask.s_addr)) {
				if (max_len < curr_rt->mask.s_addr) {
					max_len = curr_rt->mask.s_addr;
					lpm_match_rt = curr_rt;
				}
			}
			curr_rt = curr_rt->next;
		}
		/* if match, check arp cache*/
		if (lpm_match_rt) {
			printf("LPM match-not for me\n");
			struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, lpm_match_rt->gw.s_addr);
			struct sr_if *lpm_inf = sr_get_interface(sr, lpm_match_rt->interface);
			/* decrement ttl */
			ip_hdr->ip_ttl--;
			/* re-caculate checksum */
			ip_hdr->ip_sum = 0; /* re-calculate the checksum */
			uint16_t new_cksum = sizeof(sr_ip_hdr_t);
			ip_hdr->ip_sum = cksum(ip_hdr, new_cksum);

			if (arp_entry != NULL) {
				printf("ARP cache hit\n");
				/* if hit, change ethernet src/dst, send packet to next frame */
				memcpy(ether_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
				memcpy(ether_hdr->ether_shost, lpm_inf->addr, ETHER_ADDR_LEN);
				sr_send_packet(sr, packet, len, lpm_inf->name);
				print_hdr_ip((uint8_t*)ip_hdr);
				printf("Send frame to next hop\n");
				free(arp_entry);
			} else {
				/* no hit, send arp request(handle_arprequest)*/
				printf("ARP cache miss\n");
				struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, lpm_inf->name);
				handle_arpreq(req, sr);
			}
		} else {
			/* else, send icmp net unreachable(type3 code0)*/
			printf("ICMP net unreachable!\n");
			struct sr_rt* curr_rt = sr->routing_table; 
			/* check longest prefix match */
			struct sr_rt* lpm_match_rt;
			/* if the prefix matches the destination's, it's a match */
			uint32_t max_len = 0;
			while (curr_rt) {
				if ((ip_hdr->ip_src & curr_rt->mask.s_addr) == (curr_rt->dest.s_addr & curr_rt->mask.s_addr)) {
					if (max_len < curr_rt->mask.s_addr) {
						max_len = curr_rt->mask.s_addr;
						lpm_match_rt = curr_rt;
					}
				}
				curr_rt = curr_rt->next;
			} 
			/* if match, check arp cache*/
			if (lpm_match_rt) {
				printf("LPM match-net unreachable\n");
				struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, lpm_match_rt->gw.s_addr);
				struct sr_if *lpm_inf = sr_get_interface(sr, lpm_match_rt->interface);

				uint8_t *icmp_t3_pkt = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
				construct_ether_hdr(ether_hdr, (sr_ethernet_hdr_t *)icmp_t3_pkt, lpm_inf);
				/* construct ip header */
				sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(icmp_t3_pkt + sizeof(sr_ethernet_hdr_t));
				construct_ip_hdr(new_ip_hdr, ip_hdr, lpm_inf);
				/* construct icmp header */
				sr_icmp_t3_hdr_t *new_icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(icmp_t3_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
				construct_icmp_hdr(3, 0, ip_hdr, new_icmp_t3_hdr);
				if (arp_entry != NULL) {
					printf("ARP cache hit\n");
					/* if hit, change ethernet src/dst, send packet to next frame */
					sr_send_packet(sr, icmp_t3_pkt, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), lpm_inf->name);
					free(icmp_t3_pkt);
				} else {
					/* no hit, cache it to the queue and send arp request(handle_arprequest)*/
					printf("ARP cache miss\n");
					struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_src, icmp_t3_pkt, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), lpm_inf->name);
					handle_arpreq(req, sr);
				}
			} else {
				printf("LPM failed!");
			}
		}
  }
}

/* helper function: construct ethernet header */
void construct_ether_hdr(sr_ethernet_hdr_t *old_ether_hdr, sr_ethernet_hdr_t *new_ether_hdr, struct sr_if *inf) {
  memcpy(new_ether_hdr->ether_dhost, old_ether_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(new_ether_hdr->ether_shost, inf->addr, ETHER_ADDR_LEN);
  new_ether_hdr->ether_type = ether_hdr->ether_type;
}

/* construct all the ip header */
void construct_ip_hdr(sr_ip_hdr_t *new_ip_hdr, sr_ip_hdr_t *ip_hdr, struct sr_if *sr_inf) {
  new_ip_hdr->ip_src = sr_inf->ip;
  new_ip_hdr->ip_len = htons(56);
  new_ip_hdr->ip_dst = ip_hdr->ip_src;
  new_ip_hdr->ip_p = ip_protocol_icmp;
  new_ip_hdr->ip_sum = 0;
  new_ip_hdr->ip_ttl = 64;
  new_ip_hdr->ip_tos = ip_hdr->ip_tos;
  new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
}

/* helper function: construct icmp type 3 + type 11 header */
void construct_icmp_hdr(uint8_t icmp_type, uint8_t icmp_code, sr_ip_hdr_t *ip_hdr, sr_icmp_t3_hdr_t *icmp_t3_hdr) {
  memcpy(icmp_t3_hdr->data, ip_hdr, sizeof(sr_ip_hdr_t));
  icmp_t3_hdr->icmp_code = icmp_code;
  icmp_t3_hdr->icmp_type = icmp_type;
  icmp_t3_hdr->icmp_sum = 0;
  icmp_t3_hdr->next_mtu = 0;
  icmp_t3_hdr->unused = 0;
  icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
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

