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
#include "sr_rt.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
    struct sr_arpreq *request;
    request = sr->cache.requests;
    while(request) {
        struct sr_arpreq *request_next = request->next;
        handle_arpreq(request, sr);
        request = request_next;
    }
    /*for(request = sr->cache.requests; request != NULL; request = request->next) {
        handle_arpreq(request, sr);
    }*/
}

void handle_arpreq(struct sr_arpreq * request, struct sr_instance *sr) {
    time_t now = time(0); /*get current time*/
    if (difftime(now, request->sent) >= 1.0) {
        printf("in arp req?\n");
        if(request->times_sent >= 5) {
            /* send icmp host unreachable type3 code1 */
            struct sr_packet *packets = request->packets;
            while (packets) {
                struct sr_if *sr_inf = sr_get_interface(sr, packets->iface);
                sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)packets->buf;
                sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) packets->buf + sizeof(sr_ethernet_hdr_t);
                if (sr_inf == NULL) {
                    fprintf(stderr, "Packet discard: Interface not exist!");
                }
                struct sr_rt* curr_rt = sr->routing_table; 
                /* check longest prefix match */
                struct sr_rt* lpm_match_rt;
                /* if the prefix matches the destination's, it's a match */
                uint32_t len = 0;
                while (curr_rt) {
                    if ((ip_hdr->ip_src & curr_rt->mask.s_addr) == (curr_rt->dest.s_addr & curr_rt->mask.s_addr)) {
                        if (len < curr_rt->mask.s_addr) {
                            len = curr_rt->mask.s_addr;
                            lpm_match_rt = curr_rt;
                        }
                    }
                    curr_rt = curr_rt->next;
                }
                /* if match, check arp cache*/
                if (lpm_match_rt == NULL) {
                    fprintf(stderr, "Packet discard: LPM failed!");
                }
                struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, lpm_match_rt->gw.s_addr);
                struct sr_if *lpm_inf = sr_get_interface(sr, lpm_match_rt->interface);
                uint8_t *icmp_t3_pkt = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
                construct_ether_hdr(ether_hdr, (sr_ethernet_hdr_t *)icmp_t3_pkt, lpm_inf, ethertype_ip);
                /* construct ip header */
                sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(icmp_t3_pkt + sizeof(sr_ethernet_hdr_t));
                construct_ip_hdr(new_ip_hdr, ip_hdr, lpm_inf);
                /* construct icmp header */
                sr_icmp_t3_hdr_t *new_icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(icmp_t3_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                construct_icmp_hdr(3, 1, new_ip_hdr, new_icmp_t3_hdr);
                if (arp_entry) {
                    printf("ARP cache hit\n");
                    /* if hit, change ethernet src/dst, send packet to next frame */
                    sr_send_packet(sr, icmp_t3_pkt, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), lpm_inf->name);
                    free(icmp_t3_pkt);
                } else {
                    /* no hit, cache it to the queue and send arp request(handle_arprequest)*/
                    struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_src, icmp_t3_pkt, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), lpm_inf->name);
                    handle_arpreq(req, sr);
                }
                packets = packets->next;
            }
            sr_arpreq_destroy(&sr->cache,request);
        } else {
            /* send arp request broadcast*/
            struct sr_packet *packets = request->packets;
            struct sr_if *sr_inf = sr_get_interface(sr, packets->iface);
            /* if interface exists, send arp request broadcast */
            if (sr_inf) {
                /* allocate memory for arp request */
                unsigned int arp_req_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
                uint8_t *arp_req = malloc(arp_req_len);

                /* construct ethernet header */
                sr_ethernet_hdr_t *ether_arp_req_hdr = (sr_ethernet_hdr_t *)arp_req;
                /* arp request broadcast destination: FF:FF:FF:FF:FF:FF */
                memset(ether_arp_req_hdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
                memcpy(ether_arp_req_hdr->ether_shost, sr_inf->addr, ETHER_ADDR_LEN);
                ether_arp_req_hdr->ether_type = htons(ethertype_arp);

                /* construct arp request header */
                sr_arp_hdr_t *arp_req_hdr = (sr_arp_hdr_t *)(arp_req + sizeof(sr_ethernet_hdr_t));
                arp_req_hdr->ar_hrd = htons(arp_hrd_ethernet);
                arp_req_hdr->ar_pro = htons(ethertype_ip); 
                arp_req_hdr->ar_hln = ETHER_ADDR_LEN;
                arp_req_hdr->ar_pln = sizeof(uint32_t);
                arp_req_hdr->ar_op = htons(arp_op_request);
                arp_req_hdr->ar_sip = sr_inf->ip;
                arp_req_hdr->ar_tip = request->ip;
                memcpy(arp_req_hdr->ar_sha, sr_inf->addr, ETHER_ADDR_LEN); 
                memset(arp_req_hdr->ar_tha, 0x00, ETHER_ADDR_LEN);
                printf("send ARP request.\n");
                sr_send_packet(sr, arp_req, arp_req_len, sr_inf->name);
                free(arp_req);
                request->sent = now;
                request->times_sent++;
            }
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

