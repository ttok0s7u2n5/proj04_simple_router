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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

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

int send_pac(struct sr_instance* sr,
		uint32_t dip,
		uint8_t* buf,
		uint32_t len) {
	struct sr_rt *rt;
	rt = sr_findLPMentry(sr->routing_table, dip);
	sr_send_packet(sr, buf, len, rt->interface);
	fprintf(stderr, "Packet sent.\n");
	return 0;
}

int send_arp_request(struct sr_instance* sr, uint32_t dip)
{	
	fprintf(stderr, "Sending ARP request to ");
	print_addr_ip_int(ntohl(dip));
	fprintf(stderr, "... ");
	
	struct sr_rt *rt;
	rt = sr_findLPMentry(sr->routing_table, dip);
	if (rt == NULL) return DEST_NET_UNREACHABLE;
	
	struct sr_if* interface;
	interface = sr_get_interface(sr, rt->interface);
	
	sr_arp_hdr_t *arp_pac;
	arp_pac = (sr_arp_hdr_t*) malloc(sizeof(sr_arp_hdr_t));
	arp_pac->ar_hrd = htons(arp_hrd_ethernet);
	arp_pac->ar_pro = htons(ethertype_ip);
	arp_pac->ar_hln = ETHER_ADDR_LEN;
	arp_pac->ar_pln = sizeof(uint32_t);
	arp_pac->ar_op = htons(arp_op_request);
	memcpy(arp_pac->ar_sha, interface->addr, ETHER_ADDR_LEN);
	memset(arp_pac->ar_tha, 255, ETHER_ADDR_LEN);
	arp_pac->ar_sip = interface->ip;
	arp_pac->ar_tip = dip;

	sr_ethernet_hdr_t *eth_pac;
	eth_pac = (sr_ethernet_hdr_t*) malloc(sizeof(sr_ethernet_hdr_t));
	memcpy(eth_pac->ether_shost, interface->addr, ETHER_ADDR_LEN);
	memset(eth_pac->ether_dhost, 255, ETHER_ADDR_LEN);
	eth_pac->ether_type = htons(ethertype_arp);

	uint32_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	uint8_t* buf = malloc(len);
	memcpy(buf, eth_pac, sizeof(sr_ethernet_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t), arp_pac, sizeof(sr_arp_hdr_t));
	
    rt = sr_findLPMentry(sr->routing_table, dip);
    sr_send_packet(sr, buf, len, rt->interface);
    fprintf(stderr, "Packet sent.\n");

	free(arp_pac);
	free(eth_pac);
	free(buf);

	return 0;
}

int send_arp_reply(struct sr_instance* sr,
		uint32_t sip,
		uint32_t dip,
		uint8_t smac[ETHER_ADDR_LEN],
		uint8_t dmac[ETHER_ADDR_LEN])
{
	fprintf(stderr, "Sending ARP reply to ");
	print_addr_ip_int(ntohl(dip));
	fprintf(stderr, "... ");
	
	sr_arp_hdr_t *arp_pac;
	arp_pac = (sr_arp_hdr_t*) malloc(sizeof(sr_arp_hdr_t));
	arp_pac->ar_hrd = htons(arp_hrd_ethernet);
	arp_pac->ar_pro = htons(ethertype_ip);
	arp_pac->ar_hln = ETHER_ADDR_LEN;
	arp_pac->ar_pln = sizeof(uint32_t);
	arp_pac->ar_op = htons(arp_op_reply);
	memcpy(arp_pac->ar_sha, smac, ETHER_ADDR_LEN);
	memcpy(arp_pac->ar_tha, dmac, ETHER_ADDR_LEN);
	arp_pac->ar_sip = sip;
	arp_pac->ar_tip = dip;

	sr_ethernet_hdr_t *eth_pac;
	eth_pac = (sr_ethernet_hdr_t*) malloc(sizeof(sr_ethernet_hdr_t));
	memcpy(eth_pac->ether_dhost, dmac, ETHER_ADDR_LEN);
	memcpy(eth_pac->ether_shost, smac, ETHER_ADDR_LEN);
	eth_pac->ether_type = htons(ethertype_arp);

	uint32_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	uint8_t* buf = malloc(len);
	memcpy(buf, eth_pac, sizeof(sr_ethernet_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t), arp_pac, sizeof(sr_arp_hdr_t));

    struct sr_rt* rt;
	rt = sr_findLPMentry(sr->routing_table, dip);
    sr_send_packet(sr, buf, len, rt->interface);
    fprintf(stderr, "Packet sent.\n");

	free(arp_pac);
	free(eth_pac);
	free(buf);
	
	return 0;
}

int send_icmp_reply(struct sr_instance* sr,
		uint32_t sip,
		uint32_t dip,
		uint8_t smac[ETHER_ADDR_LEN],
		uint8_t dmac[ETHER_ADDR_LEN],
		uint16_t ip_id,
		uint8_t *icmp_data,
		uint16_t icmp_data_len)
{
	fprintf(stderr, "Sending ICMP Echo reply to ");
	print_addr_ip_int(ntohl(dip));
	fprintf(stderr, "... ");

	sr_icmp_hdr_t *icmp_pac;
	uint32_t icmp_len = sizeof(sr_icmp_hdr_t) + icmp_data_len;
	icmp_pac = malloc(icmp_len);
	icmp_pac->icmp_type = 0;
	icmp_pac->icmp_code = 0;
	memcpy((uint8_t*)icmp_pac + sizeof(sr_icmp_hdr_t), icmp_data, icmp_data_len);
	icmp_pac->icmp_sum = 0;
	icmp_pac->icmp_sum = cksum(icmp_pac, icmp_len);

	sr_ip_hdr_t *ip_pac;
	ip_pac = (sr_ip_hdr_t*) malloc(sizeof(sr_ip_hdr_t));
	ip_pac->ip_v = 4;
	ip_pac->ip_hl = 5;
	ip_pac->ip_tos = 0;
	ip_pac->ip_len = htons(sizeof(sr_ip_hdr_t) + icmp_len);
	ip_pac->ip_id = htons(ip_id);
	ip_pac->ip_off = htons(IP_DF);
	ip_pac->ip_ttl = 64;
	ip_pac->ip_p = ip_protocol_icmp;
	ip_pac->ip_src = sip;
	ip_pac->ip_dst = dip;
	ip_pac->ip_sum = 0;
	ip_pac->ip_sum = cksum(ip_pac, sizeof(sr_ip_hdr_t));

	sr_ethernet_hdr_t *eth_pac;
	eth_pac = (sr_ethernet_hdr_t*)malloc(sizeof(sr_ethernet_hdr_t));
	memcpy(eth_pac->ether_dhost, dmac, ETHER_ADDR_LEN);
	memcpy(eth_pac->ether_shost, smac, ETHER_ADDR_LEN);
	eth_pac->ether_type = htons(ethertype_ip);

	uint32_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + icmp_len;
	uint8_t* buf = malloc(len);
	memcpy(buf, eth_pac, sizeof(sr_ethernet_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t), ip_pac, sizeof(sr_ip_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_pac, icmp_len);

	struct sr_rt* rt;
    rt = sr_findLPMentry(sr->routing_table, dip);
    sr_send_packet(sr, buf, len, rt->interface);
    fprintf(stderr, "Packet sent.\n");
	
	free(icmp_pac);
	free(ip_pac);
	free(eth_pac);
	free(buf);

	return 0;
}

int send_icmp_exception(struct sr_instance* sr,
		uint32_t dip,
		uint8_t dmac[ETHER_ADDR_LEN],
		uint16_t ip_id,
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
	ip_pac->ip_id = htons(ip_id);
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
    struct sr_rt *rt;              /* routing table entry */
    struct sr_arpentry *entry;  /* ARP table entry in ARP cache */
    struct sr_arpreq *req;      /* request entry in ARP cache */
    struct sr_packet *en_pck;      /* encapsulated packet in ARP cache */
    
	printf("\n*** -> Received packet of length %d\n", len);

	/* validation */
    if (len < sizeof(struct sr_ethernet_hdr))
        return;
    len_r = len - sizeof(struct sr_ethernet_hdr);

	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    
    /* IP */
	if (eth_hdr->ether_type == htons(ethertype_ip))
    {
        /* validation */
        if (len_r < sizeof(struct sr_ip_hdr))
            return;
        
		sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
		
		fprintf(stderr, "Received IP packet (Source: ");
		print_addr_ip_int(ntohl(ip_hdr->ip_src));
		fprintf(stderr, " Target: ");
		print_addr_ip_int(ntohl(ip_hdr->ip_dst));
		fprintf(stderr, " ID: %u)\n", htons(ip_hdr->ip_id));

		for (ifc = sr->if_list; ifc != NULL; ifc = ifc->next)
        {
			if (ifc->ip == ip_hdr->ip_dst)
            {
                break;
            }
        }
        if (ifc != NULL)
        {
            if (ip_hdr->ip_p == ip_protocol_icmp)
            {
                /* validation */
                if (len_r < sizeof(struct sr_icmp_hdr))
                    return;
                
                sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                /* Echo Reply */
                if (icmp_hdr->icmp_type == 8)
                {
                    /* validation */
                    checksum = icmp_hdr->icmp_sum;
                    icmp_hdr->icmp_sum = 0;
                    if (checksum != cksum(icmp_hdr, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr)))
                        return;
                    icmp_hdr->icmp_sum = checksum;
                    
                    send_icmp_reply(sr,
							ip_hdr->ip_dst,
							ip_hdr->ip_src,
							eth_hdr->ether_dhost,
							eth_hdr->ether_shost,
							htons(ip_hdr->ip_id) + 1,
							packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t),
							htons(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t) - sizeof(sr_icmp_hdr_t));
                    return;
                }
                else
                    return;
            }
            /* Port Unreachable */
            else if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp)
            {
                /* validation */
                if (len_r + sizeof(struct sr_ip_hdr) < ICMP_DATA_SIZE)
                    return;
                
                send_icmp_exception(sr, ip_hdr->ip_src, eth_hdr->ether_shost, htons(ip_hdr->ip_id) + 1, packet + sizeof(sr_ethernet_hdr_t), htons(ip_hdr->ip_len), PORT_UNREACHABLE);
                return;
            }
            else
                return;
        }
        /* ifc == NULL */
        else {
            int res;
            /* refer routing table */
            rt = sr_findLPMentry(sr->routing_table, ip_hdr->ip_dst);
            /* routing table hit */
            if (rt != NULL)
            {
                /* TTL Exceeded */
                if (ip_hdr->ip_ttl == 1)
                {
                    /* validation */
                    if (len_r + sizeof(struct sr_ip_hdr) < ICMP_DATA_SIZE)
                        return;
                    fprintf(stderr, "TTL Exceeded.\n");
                    send_icmp_exception(sr, ip_hdr->ip_src, eth_hdr->ether_shost, htons(ip_hdr->ip_id) + 1, packet + sizeof(sr_ethernet_hdr_t), htons(ip_hdr->ip_len), TTL_EXCEEDED);
                }
                /* TTL not expired (i_hdr0->ip_ttl != 1) -> Forward the datagram */
                else
                {
                    fprintf(stderr, "Forwarding the data...\n");
                    res = forward_pac(sr, packet, len);
                    if (res != 0)
                    {
                        fprintf(stderr, "Forwarding failed.\n");
                        send_icmp_exception(sr, ip_hdr->ip_src, eth_hdr->ether_shost, htons(ip_hdr->ip_id) + 1, packet + sizeof(sr_ethernet_hdr_t), htons(ip_hdr->ip_len), res);
                        return;
                    }
                }
            }
            /* Destination Unreachable */
            else
            {
                /* validation */
                if (len_r + sizeof(struct sr_ip_hdr) < ICMP_DATA_SIZE)
                    return;
                fprintf(stderr, "Destination Unreachable.\n");
                send_icmp_exception(sr, ip_hdr->ip_src, eth_hdr->ether_shost, htons(ip_hdr->ip_id) + 1, packet + sizeof(sr_ethernet_hdr_t), htons(ip_hdr->ip_len), DEST_NET_UNREACHABLE);
            }
            return;
		}
	}
    /* ARP */
    else if (eth_hdr->ether_type == htons(ethertype_arp))
    {
        /* validation */
        if (len_r < sizeof(struct sr_arp_hdr))
            return;
        
		sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
        
		ifc = sr_get_interface(sr, interface);
        if (ifc->ip == arp_hdr->ar_tip)
        {
            if (arp_hdr->ar_op == htons(arp_op_request))
            {
                fprintf(stderr, "Received ARP request (Source: ");
                print_addr_ip_int(ntohl(arp_hdr->ar_sip));
                fprintf(stderr, " Target: ");
                print_addr_ip_int(ntohl(arp_hdr->ar_tip));
                fprintf(stderr, ")\n");
                
                fprintf(stderr, "Sending ARP reply to ");
                print_addr_ip_int(ntohl(arp_hdr->ar_sip));
                fprintf(stderr, "... ");
                
                sr_arp_hdr_t *arp_pac;
                arp_pac = (sr_arp_hdr_t*) malloc(sizeof(sr_arp_hdr_t));
                arp_pac->ar_hrd = htons(arp_hrd_ethernet);
                arp_pac->ar_pro = htons(ethertype_ip);
                arp_pac->ar_hln = ETHER_ADDR_LEN;
                arp_pac->ar_pln = sizeof(uint32_t);
                arp_pac->ar_op = htons(arp_op_reply);
                memcpy(arp_pac->ar_sha, ifc->addr, ETHER_ADDR_LEN);
                memcpy(arp_pac->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                arp_pac->ar_sip = arp_hdr->ar_tip;
                arp_pac->ar_tip = arp_hdr->ar_sip;

                sr_ethernet_hdr_t *eth_pac;
                eth_pac = (sr_ethernet_hdr_t*) malloc(sizeof(sr_ethernet_hdr_t));
                memcpy(eth_pac->ether_shost, ifc->addr, ETHER_ADDR_LEN);
                memcpy(eth_pac->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                eth_pac->ether_type = htons(ethertype_arp);

                uint32_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
                uint8_t* buf = malloc(len);
                memcpy(buf, eth_pac, sizeof(sr_ethernet_hdr_t));
                memcpy(buf + sizeof(sr_ethernet_hdr_t), arp_pac, sizeof(sr_arp_hdr_t));

                rt = sr_findLPMentry(sr->routing_table, arp_pac->ar_tip);
                sr_send_packet(sr, buf, len, rt->interface);
                fprintf(stderr, "ARP reply packet sent.\n");

                free(arp_pac);
                free(eth_pac);
                free(buf);
                
                return;
            }
            else if (arp_hdr->ar_op == htons(arp_op_reply))
            {
                fprintf(stderr, "Received ARP reply (Source: ");
                print_addr_ip_int(ntohl(arp_hdr->ar_sip));
                fprintf(stderr, " Target: ");
                print_addr_ip_int(ntohl(arp_hdr->ar_tip));
                fprintf(stderr, ")\n");
                
                req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
            
                if (req != NULL) {
                    for (en_pck = req->packets; en_pck != NULL; en_pck = en_pck->next)
                    {
                        uint8_t *nbuf = malloc(en_pck->len);
                        unsigned int nlen = en_pck->len;
                        memcpy(nbuf, en_pck->buf, en_pck->len);

                        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(nbuf);
                        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(nbuf + sizeof(sr_ethernet_hdr_t));
                        
                        fprintf(stderr, "Sending packet in queue (");
                        fprintf(stderr, "Source: ");
                        print_addr_ip_int(ntohl(ip_hdr->ip_src));
                        fprintf(stderr, " Target: ");
                        print_addr_ip_int(ntohl(ip_hdr->ip_dst));
                        fprintf(stderr, " ID: %u)...\n", htons(ip_hdr->ip_id));
                        
                        rt = sr_findLPMentry(sr->routing_table, ip_hdr->ip_dst);

                        ifc = sr_get_interface(sr, rt->interface);
                        entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);

                        if (entry)
                        {
                            memcpy(eth_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
                            memcpy(eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
                        }
                        else
                        {
                            fprintf(stderr, "MAC not found in ARP cache, queuing...\n");
                            req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, nbuf, nlen, rt->interface);
                            sr_arpcache_handle_arpreq(sr, req);
                            return;
                        }
                        
                        ip_hdr->ip_ttl--;
                        ip_hdr->ip_sum = 0;
                        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
                        
                        rt = sr_findLPMentry(sr->routing_table, ip_hdr->ip_dst);
                        sr_send_packet(sr, nbuf, nlen, rt->interface);
                        fprintf(stderr, "ARP request pending packet sent.\n");
                        free(nbuf);
                    }
                    sr_arpreq_destroy(&(sr->cache), req);
                    return;
                }
                else
                    return;
            }
            else
                return;
        }
        else
            return;
	}
    else
        return;
}

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

