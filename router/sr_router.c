/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * 2021 Spring EE323 Computer Network
 * Project #4 Simple Router
 * Author: Heewon Yang
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#define DEST_NET_UNREACHABLE   1
#define DEST_HOST_UNREACHABLE  2
#define PORT_UNREACHABLE       3
#define TTL_EXCEEDED           4

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

int send_icmp_exception(struct sr_instance* sr,
		uint32_t dip,
		uint8_t dmac[ETHER_ADDR_LEN],
		uint8_t *icmp_data,
		uint16_t icmp_data_len,
		int icmp_exeption_type)
{
	fprintf(stderr, "Sending ICMP packet to ");
	print_addr_ip_int(ntohl(dip));
	
	struct sr_rt *rt;
	rt = sr_findLPMentry(sr->routing_table, dip);
	struct sr_if *interface;
	interface = sr_get_interface(sr, rt->interface);
	
	sr_icmp_t3_hdr_t *icmp_pac;
	uint32_t icmp_len = sizeof(sr_icmp_t3_hdr_t) + icmp_data_len;
	icmp_pac = malloc(icmp_len);

	if (icmp_exeption_type == DEST_NET_UNREACHABLE) {
		icmp_pac->icmp_type = 3;
		icmp_pac->icmp_code = 0;
		fprintf(stderr, " (Destination net unreachable)... ");
	} else if (icmp_exeption_type == DEST_HOST_UNREACHABLE) {
		icmp_pac->icmp_type = 3;
		icmp_pac->icmp_code = 1;
		fprintf(stderr, " (Destination host unreachable)... ");
	} else if (icmp_exeption_type == PORT_UNREACHABLE) {
		icmp_pac->icmp_type = 3;
		icmp_pac->icmp_code = 3;
		fprintf(stderr, " (Port unreachable)... ");
	} else if (icmp_exeption_type == TTL_EXCEEDED) {
		icmp_pac->icmp_type = 11;
		icmp_pac->icmp_code = 0;
		fprintf(stderr, " (TTL exceeded)... ");
	}

	memcpy((uint8_t*)icmp_pac + sizeof(sr_icmp_t3_hdr_t), icmp_data, icmp_data_len);
	icmp_pac->icmp_sum = 0;
	icmp_pac->icmp_sum = cksum(icmp_pac, icmp_len);

	sr_ip_hdr_t *ip_pac;
	ip_pac = (sr_ip_hdr_t*) malloc(sizeof(sr_ip_hdr_t));
	ip_pac->ip_v = 4;
	ip_pac->ip_hl = 5;
	ip_pac->ip_tos = 0;
	ip_pac->ip_len = htons(sizeof(sr_ip_hdr_t) + icmp_len);
	ip_pac->ip_off = htons(IP_DF);
	ip_pac->ip_ttl = 64;
	ip_pac->ip_p = ip_protocol_icmp;
	ip_pac->ip_src = interface->ip;
	ip_pac->ip_dst = dip;
	ip_pac->ip_sum = 0;
	ip_pac->ip_sum = cksum(ip_pac, sizeof(sr_ip_hdr_t));

	sr_ethernet_hdr_t *eth_pac;
	eth_pac = (sr_ethernet_hdr_t*)malloc(sizeof(sr_ethernet_hdr_t));
	memcpy(eth_pac->ether_dhost, dmac, ETHER_ADDR_LEN);
	memcpy(eth_pac->ether_shost, interface->addr, ETHER_ADDR_LEN);
	eth_pac->ether_type = htons(ethertype_ip);

	uint32_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + icmp_len;
	uint8_t* buf = malloc(len);
	memcpy(buf, eth_pac, sizeof(sr_ethernet_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t), ip_pac, sizeof(sr_ip_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_pac, icmp_len);
	
    rt = sr_findLPMentry(sr->routing_table, dip);
    sr_send_packet(sr, buf, len, rt->interface);
    fprintf(stderr, "Packet sent.\n");

	free(icmp_pac);
	free(ip_pac);
	free(eth_pac);
	free(buf);

	return 0;
}

int forward_pac(struct sr_instance *sr,
		uint8_t* pac,
		uint32_t len) {
	uint8_t *buf = malloc(len);
	memcpy(buf, pac, len);

	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) buf;
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));
	
	fprintf(stderr, "Forwarding IP packet to ");
	print_addr_ip_int(ntohl(ip_hdr->ip_dst));
	fprintf(stderr, "... ");
	
	struct sr_rt *rt;
	rt = sr_findLPMentry(sr->routing_table, ip_hdr->ip_dst);

	struct sr_if* interface;
	interface = sr_get_interface(sr, rt->interface);
	struct sr_arpentry* entry;
	entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);

	if (entry)
    {
		memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
		memcpy(eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
	}
    else
    {
		fprintf(stderr, "MAC not found in ARP cache, queuing...\n");
		struct sr_arpreq *req;
		req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, buf, len, rt->interface);
		sr_arpcache_handle_arpreq(sr, req);
		return 0;
	}
	
	ip_hdr->ip_ttl--;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    sr_send_packet(sr, buf, len, rt->interface);
    fprintf(stderr, "Packet sent.\n");
	
	free(buf);

	return 0;
}

int ip_black_list(struct sr_ip_hdr* iph)
{
    int blk = 0;
    char ip_blacklist[20]="10.0.2.0";
    char mask[20]="255.255.255.0";
    /**************** fill in code here *****************/
    struct in_addr target;
    struct in_addr black;
    struct in_addr masks;
    target.s_addr = iph->ip_dst;
    if (inet_aton(ip_blacklist, &black) == 0)
    {
        exit(EXIT_FAILURE);
    }
    if (inet_aton(mask, &masks) == 0)
    {
        exit(EXIT_FAILURE);
    }
    if ((target.s_addr & masks.s_addr) == black.s_addr)
    {
        fprintf(stderr, "Received blacklist IP address.\n");
        blk = 1;
    }
    else
    {
        fprintf(stderr, "Received safe IP address.\n");
        blk = 0;
    }
    if (blk == 1) {
        char *target_ip = inet_ntoa(target);
        fprintf(stderr, "[IP blocked] : %s\n", target_ip);
    }
    /****************************************************/
    return blk;
}

void sr_handlepacket(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        char *interface /* lent */)
{
	assert(sr);
	assert(packet);
	assert(interface);
    
    /*
        We provide local variables used in the reference solution.
        You can add or ignore local variables.
    */
    uint8_t *new_pck;      /* new packet */
    unsigned int new_len; /* length of new_pck */

    unsigned int len_r; /* length remaining, for validation */
    uint16_t checksum;    /* checksum, for validation */

    struct sr_ethernet_hdr *e_hdr0, *e_hdr; /* Ethernet headers */
    struct sr_ip_hdr *i_hdr0, *i_hdr;        /* IP headers */
    struct sr_arp_hdr *a_hdr0, *a_hdr;        /* ARP headers */
    struct sr_icmp_hdr *ic_hdr0;            /* ICMP header */
    struct sr_icmp_t3_hdr *ict3_hdr;        /* ICMP type3 header */

    struct sr_if *ifc;             /* router interface */
    uint32_t ipaddr;               /* IP address */
    struct sr_rt *rtentry;              /* routing table entry */
    struct sr_arpentry *arpentry;  /* ARP table entry in ARP cache */
    struct sr_arpreq *arpreq;      /* request entry in ARP cache */
    struct sr_packet *en_pck;      /* encapsulated packet in ARP cache */
    
	fprintf(stderr, "\n*** -> Received packet of length %d\n", len);

	/* validation */
    if (len < sizeof(struct sr_ethernet_hdr))
        return;
    len_r = len - sizeof(struct sr_ethernet_hdr);
    e_hdr0 = (struct sr_ethernet_hdr *)packet; /* e_hdr0 set */

    /* IP packet arrived */
    if (e_hdr0->ether_type == htons(ethertype_ip))
    {
        /* validation */
        if (len_r < sizeof(struct sr_ip_hdr))
            return;

        len_r = len_r - sizeof(struct sr_ip_hdr);
        i_hdr0 = (struct sr_ip_hdr *)(((uint8_t *)e_hdr0) + sizeof(struct sr_ethernet_hdr)); /* i_hdr0 set */

        if (i_hdr0->ip_v != 0x4)
            return;

        checksum = i_hdr0->ip_sum;
        i_hdr0->ip_sum = 0;
        if (checksum != cksum(i_hdr0, sizeof(struct sr_ip_hdr)))
            return;
        i_hdr0->ip_sum = checksum;

        /* check destination */
        for (ifc = sr->if_list; ifc != NULL; ifc = ifc->next)
        {
            if (i_hdr0->ip_dst == ifc->ip)
                break;
        }

        /* check ip black list */
        if (ip_black_list(i_hdr0))
        {
            /* Drop the packet */
            return;
        }
        
        fprintf(stderr, "Received IP packet (Source: ");
        print_addr_ip_int(ntohl(i_hdr0->ip_src));
        fprintf(stderr, " Target: ");
        print_addr_ip_int(ntohl(i_hdr0->ip_dst));
        fprintf(stderr, ")\n");

        /* destined to router interface */
        if (ifc != NULL)
        {
            /* with ICMP */
            if (i_hdr0->ip_p == ip_protocol_icmp)
            {
                /* validation */
                if (len_r < sizeof(struct sr_icmp_hdr))
                    return;

                ic_hdr0 = (struct sr_icmp_hdr *)(((uint8_t *)i_hdr0) + sizeof(struct sr_ip_hdr)); /* ic_hdr0 set */

                /* echo request type */
                if (ic_hdr0->icmp_type == 0x08)
                {
                    /* validation */
                    checksum = ic_hdr0->icmp_sum;
                    ic_hdr0->icmp_sum = 0;
                    if (checksum != cksum(ic_hdr0, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr)))
                        return;
                    ic_hdr0->icmp_sum = checksum;

                    /* modify to echo reply */
                    i_hdr0->ip_ttl = INIT_TTL;
                    ipaddr = i_hdr0->ip_src;
                    i_hdr0->ip_src = i_hdr0->ip_dst;
                    i_hdr0->ip_dst = ipaddr;
                    i_hdr0->ip_sum = 0;
                    i_hdr0->ip_sum = cksum(i_hdr0, sizeof(struct sr_ip_hdr));
                    ic_hdr0->icmp_code = 0x00; /* new */
                    ic_hdr0->icmp_type = 0x00;
                    ic_hdr0->icmp_sum = 0;
                    ic_hdr0->icmp_sum = cksum(ic_hdr0, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));
                    rtentry = sr_findLPMentry(sr->routing_table, i_hdr0->ip_dst);
                    if (rtentry != NULL)
                    {
                        fprintf(stderr, "[Echo Reply]\n");
                        ifc = sr_get_interface(sr, rtentry->interface);
                        memcpy(e_hdr0->ether_shost, ifc->addr, ETHER_ADDR_LEN);
                        arpentry = sr_arpcache_lookup(&(sr->cache), ipaddr);
                        if (arpentry != NULL)
                        {
                            memcpy(e_hdr0->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
                            free(arpentry);
                            
                            fprintf(stderr, "Sending ICMP Echo reply to ");
                            print_addr_ip_int(ntohl(ipaddr));
                            fprintf(stderr, "... ");
                            
                            /* send */
                            sr_send_packet(sr, packet, len, rtentry->interface);
                        }
                        else
                        {
                            fprintf(stderr, "MAC not found in ARP cache, queuing...\n");
                            /* queue */
                            arpreq = sr_arpcache_queuereq(&(sr->cache), ipaddr, packet, len, rtentry->interface);
                            sr_arpcache_handle_arpreq(sr, arpreq);
                        }
                    }

                    /* done */
                    return;
                }

                /* other types */
                else
                    return;
            }
            /* with TCP or UDP -> Port Unreachable */
            else if (i_hdr0->ip_p == ip_protocol_tcp || i_hdr0->ip_p == ip_protocol_udp)
            {
                /* validation */
                if (len_r + sizeof(struct sr_ip_hdr) < ICMP_DATA_SIZE)
                    return;

                /* generate ICMP port unreachable packet */
                new_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
                new_pck = (uint8_t *) calloc(1, new_len);
                
                /**************** fill in code here *****************/
                /* ICMP header */
                ict3_hdr = (struct sr_icmp_t3_hdr *)(new_pck + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
                memcpy(ict3_hdr->data, i_hdr0, ICMP_DATA_SIZE);
                ict3_hdr->icmp_code = 0x03; /* code : 3 */
                ict3_hdr->icmp_type = 0x03; /* type : 3 */
                ict3_hdr->icmp_sum = 0;
                ict3_hdr->icmp_sum = cksum(ict3_hdr, new_len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));
                
                /* IP header */
                i_hdr = (struct sr_ip_hdr *)(new_pck + sizeof(struct sr_ethernet_hdr));
                i_hdr->ip_p = ip_protocol_icmp;
                i_hdr->ip_hl = 0x5;
                i_hdr->ip_v = 0x4;
                i_hdr->ip_tos = 0x00;
                int ip_length = sizeof(struct sr_icmp_t3_hdr) + ((int)(4 * i_hdr->ip_hl));
                i_hdr->ip_len = htons(ip_length);
                i_hdr->ip_id = 0x0000;
                i_hdr->ip_off = 0x0000;
                
                i_hdr->ip_ttl = INIT_TTL;
                ipaddr = i_hdr0->ip_src;
                i_hdr->ip_src = i_hdr0->ip_dst;
                i_hdr->ip_dst = ipaddr; /* i_hdr0->ip_src; */
                i_hdr->ip_sum = 0;
                i_hdr->ip_sum = cksum(i_hdr, sizeof(struct sr_ip_hdr));
                
                /* Ethernet header */
                e_hdr = (struct sr_ethernet_hdr *)(new_pck);
                e_hdr->ether_type = htons(ethertype_ip);
                
                /* refer routing table */
                rtentry = sr_findLPMentry(sr->routing_table, i_hdr->ip_dst);
                
                /* routing table hit */
                if (rtentry != NULL)
                {
                    fprintf(stderr, "[Port Unreachable]\n");
                    ifc = sr_get_interface(sr, rtentry->interface);
                    
                    /* set src MAC addr */
                    memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
                    
                    /* refer ARP table */
                    arpentry = sr_arpcache_lookup(&(sr->cache), rtentry->gw.s_addr);
                    if (arpentry != NULL)
                    {
                        /* set dst MAC addr */
                        memcpy(e_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
                        free(arpentry);
                        
                        fprintf(stderr, "Sending ICMP Port Unreachable to ");
                        print_addr_ip_int(ntohl(ipaddr));
                        fprintf(stderr, "... ");
                        
                        /* send */
                        sr_send_packet(sr, new_pck, new_len, rtentry->interface);
                    }
                    else
                    {
                        fprintf(stderr, "MAC not found in ARP cache, queuing...\n");
                        /* queue */
                        arpreq = sr_arpcache_queuereq(&(sr->cache), rtentry->gw.s_addr, new_pck, new_len, rtentry->interface);
                        sr_arpcache_handle_arpreq(sr, arpreq);
                    }
                }
                
                /*send_icmp_exception(sr, i_hdr0->ip_src, e_hdr0->ether_shost, packet + sizeof(sr_ethernet_hdr_t), htons(i_hdr0->ip_len), PORT_UNREACHABLE);*/
                free(new_pck);
                /* done */
                /*****************************************************/
                return;
            }
            /* with others */
            else
                return;
        }
        /* destined elsewhere, forward */
        else
        {
            /* refer routing table */
            rtentry = sr_findLPMentry(sr->routing_table, i_hdr0->ip_dst);
            
            /* routing table hit */
            if (rtentry != NULL)
            {
                /* check TTL expiration */
                /* TTL expired -> Time Exceeded */
                if (i_hdr0->ip_ttl == 1)
                {
                    /**************** fill in code here *****************/
                    /* validation */
                    if (len_r + sizeof(struct sr_ip_hdr) < ICMP_DATA_SIZE)
                        return;
                    
                    fprintf(stderr, "[TTL Exceeded]\n");
                    send_icmp_exception(sr, i_hdr0->ip_src, e_hdr0->ether_shost, packet + sizeof(sr_ethernet_hdr_t), htons(i_hdr0->ip_len), TTL_EXCEEDED);
                    /*free(new_pck);*/
                    /* done */
                    /*****************************************************/
                    return;
                }
                /* TTL not expired (i_hdr0->ip_ttl != 1) -> Forward the datagram */
                else
                {
                    /**************** fill in code here *****************/
                    fprintf(stderr, "[Forwarding]\n");
                    int r;
                    if ((r = forward_pac(sr, packet, len)) != 0)
                    {
                        fprintf(stderr, "Forwarding failed.\n");
                        send_icmp_exception(sr, i_hdr0->ip_src, e_hdr0->ether_shost, packet + sizeof(sr_ethernet_hdr_t), htons(i_hdr0->ip_len), r);
                    }
                    /*****************************************************/
                    /* done */
                    return;
                }
            }
            /* routing table miss -> Destination Unreachable */
            else
            {
                /**************** fill in code here *****************/
                /* validation */
                if (len_r + sizeof(struct sr_ip_hdr) < ICMP_DATA_SIZE)
                    return;
                
                fprintf(stderr, "[Destination Unreachable]\n");
                send_icmp_exception(sr, i_hdr0->ip_src, e_hdr0->ether_shost, packet + sizeof(sr_ethernet_hdr_t), htons(i_hdr0->ip_len), DEST_NET_UNREACHABLE);
                /*free(new_pck);*/
                /* done */
                /*****************************************************/
                return;
            }
		}
	}
    /* ARP packet arrived */
    else if (e_hdr0->ether_type == htons(ethertype_arp))
    {
        /* validation */
        if (len_r < sizeof(struct sr_arp_hdr))
            return;
        
		a_hdr0 = (struct sr_arp_hdr *)(packet + sizeof(struct sr_ethernet_hdr)); /* a_hdr0 set */
        
		/* destined to me */
        ifc = sr_get_interface(sr, interface);
        if (a_hdr0->ar_tip == ifc->ip)
        {
            /* request code */
            if (a_hdr0->ar_op == htons(arp_op_request))
            {
                /**************** fill in code here *****************/
                fprintf(stderr, "Received ARP request (Source: ");
                print_addr_ip_int(ntohl(a_hdr0->ar_sip));
                fprintf(stderr, " Target: ");
                print_addr_ip_int(ntohl(a_hdr0->ar_tip));
                fprintf(stderr, ")\n");
                
                fprintf(stderr, "[ARP Reply]\n");
                fprintf(stderr, "Sending ARP reply to ");
                print_addr_ip_int(ntohl(a_hdr0->ar_sip));
                fprintf(stderr, "... ");
                
                /* generate reply */
                new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
                new_pck = (uint8_t *)malloc(new_len);
                
                /* ARP header */
                sr_arp_hdr_t *arp_pac;
                arp_pac = (sr_arp_hdr_t*) malloc(sizeof(sr_arp_hdr_t));
                arp_pac->ar_hrd = htons(arp_hrd_ethernet);
                arp_pac->ar_pro = htons(ethertype_ip);
                arp_pac->ar_hln = ETHER_ADDR_LEN;
                arp_pac->ar_pln = sizeof(uint32_t);
                arp_pac->ar_op = htons(arp_op_reply);
                memcpy(arp_pac->ar_sha, ifc->addr, ETHER_ADDR_LEN);
                memcpy(arp_pac->ar_tha, a_hdr0->ar_sha, ETHER_ADDR_LEN);
                arp_pac->ar_sip = a_hdr0->ar_tip;
                arp_pac->ar_tip = a_hdr0->ar_sip;

                /* Ethernet header */
                sr_ethernet_hdr_t *eth_pac;
                eth_pac = (sr_ethernet_hdr_t*) malloc(sizeof(sr_ethernet_hdr_t));
                memcpy(eth_pac->ether_shost, ifc->addr, ETHER_ADDR_LEN);
                memcpy(eth_pac->ether_dhost, a_hdr0->ar_sha, ETHER_ADDR_LEN);
                eth_pac->ether_type = htons(ethertype_arp);
                
                memcpy(new_pck, eth_pac, sizeof(sr_ethernet_hdr_t));
                memcpy(new_pck + sizeof(sr_ethernet_hdr_t), arp_pac, sizeof(sr_arp_hdr_t));

                /* refer routing table */
                rtentry = sr_findLPMentry(sr->routing_table, arp_pac->ar_tip);
                if (rtentry == NULL) return;
                
                /* send */
                sr_send_packet(sr, new_pck, new_len, rtentry->interface);
                fprintf(stderr, "ARP reply packet sent.\n");

                free(arp_pac);
                free(eth_pac);
                free(new_pck);
                /* done */
                /*****************************************************/
                return;
            }
            /* reply code */
            else if (a_hdr0->ar_op == htons(arp_op_reply))
            {
                /**************** fill in code here *****************/
                fprintf(stderr, "Received ARP reply (Source: ");
                print_addr_ip_int(ntohl(a_hdr0->ar_sip));
                fprintf(stderr, " Target: ");
                print_addr_ip_int(ntohl(a_hdr0->ar_tip));
                fprintf(stderr, ")\n");
                
                fprintf(stderr, "[Pending Requests]\n");
                
                arpreq = sr_arpcache_insert(&sr->cache, a_hdr0->ar_sha, a_hdr0->ar_sip);
            
                if (arpreq != NULL) {
                    for (en_pck = arpreq->packets; en_pck != NULL; en_pck = en_pck->next)
                    {
                        /* generate request */
                        uint8_t *nbuf = malloc(en_pck->len);
                        unsigned int nlen = en_pck->len;
                        memcpy(nbuf, en_pck->buf, en_pck->len);
                        int self_generated_flag = 0;

                        struct sr_ethernet_hdr *en_e_hdr = (struct sr_ethernet_hdr *)(nbuf);
                        struct sr_ip_hdr *en_i_hdr = (struct sr_ip_hdr *)(nbuf + sizeof(sr_ethernet_hdr_t));
                        
                        rtentry = sr_findLPMentry(sr->routing_table, en_i_hdr->ip_dst);
                        if (rtentry == NULL) return;
                        
                        /* routing table hit */
                        ifc = sr_get_interface(sr, rtentry->interface);
                        
                        /* refer ARP table */
                        arpentry = sr_arpcache_lookup(&sr->cache, en_i_hdr->ip_dst);
                        if (arpentry != NULL)
                        {
                            fprintf(stderr, "Sending a pending request to ");
                            print_addr_ip_int(ntohl(en_i_hdr->ip_dst));
                            fprintf(stderr, "... ");
                            
                            memcpy(en_e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
                            memcpy(en_e_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
                        }
                        else
                        {
                            fprintf(stderr, "MAC not found in ARP cache, queuing...\n");
                            arpreq = sr_arpcache_queuereq(&sr->cache, en_i_hdr->ip_dst, nbuf, nlen, rtentry->interface);
                            sr_arpcache_handle_arpreq(sr, arpreq);
                            return;
                        }
                        
                        /* check if there are self-generated packets */
                        for (ifc = sr->if_list; ifc != NULL; ifc = ifc->next)
                        {
                            if (en_i_hdr->ip_src == ifc->ip)
                            {
                                self_generated_flag = 1;
                                break;
                            }
                        }
                        /* decrement TTL except for self-generated packets */
                        if (self_generated_flag == 0)
                        {
                            en_i_hdr->ip_ttl = en_i_hdr->ip_ttl - 0x01;
                        }
                        en_i_hdr->ip_sum = 0;
                        en_i_hdr->ip_sum = cksum(en_i_hdr, sizeof(struct sr_ip_hdr));
                        
                        rtentry = sr_findLPMentry(sr->routing_table, en_i_hdr->ip_dst);
                        sr_send_packet(sr, nbuf, nlen, rtentry->interface);
                        free(nbuf);
                    }
                    fprintf(stderr, "Pending packets all sent.\n");
                    /* ARP destruction */
                    sr_arpreq_destroy(&(sr->cache), arpreq);
                    /* done */
                    /*****************************************************/
                    return;
                }
                
                /* no exist */
                else
                    return;
            }
            
            /* other codes */
            else
                return;
        }
    
        /* destined to others */
        else
            return;
    }
    
    /* other packet arrived */
    else
        return;

} /* end sr_handlepacket */

struct sr_rt *sr_findLPMentry(struct sr_rt *rtable, uint32_t ip_dst)
{
    struct sr_rt *entry, *lpmentry = NULL;
    uint32_t mask, lpmmask = 0;

    ip_dst = ntohl(ip_dst);

    /* scan routing table */
    for (entry = rtable; entry != NULL; entry = entry->next)
    {
        mask = ntohl(entry->mask.s_addr);
        /* longest match so far */
        if ((ip_dst & mask) == (ntohl(entry->dest.s_addr) & mask) && mask > lpmmask)
        {
            lpmentry = entry;
            lpmmask = mask;
        }
    }

    return lpmentry;
}

