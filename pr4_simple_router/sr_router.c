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
void sr_init(struct sr_instance *sr)
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
* Method: ip_black_list(struct sr_ip_hdr *iph)
* Scope:  Local
*
* This method is called each time the sr_handlepacket() is called.
* Block IP addresses in the blacklist and print the log.
* - Format : "[IP blocked] : <IP address>"
* - e.g.) [IP blocked] : 10.0.2.100
*
*---------------------------------------------------------------------*/
int ip_black_list(struct sr_ip_hdr *iph)
{
	char ip_blacklist[20] = "10.0.2.0"; /* DO NOT MODIFY */
	char mask[20] = "255.255.255.0"; /* DO NOT MODIFY */
	/**************** fill in code here *****************/
    
    struct in_addr ip0;
	struct in_addr ip1;
    struct in_addr ip_blk;
    struct in_addr mask_blk;
    inet_aton(ip_blacklist, &ip_blk);
    inet_aton(mask, &mask_blk);
    ip0.s_addr = iph->ip_src;
    ip1.s_addr = iph->ip_dst;

	
	char str[16];
    if (((ip1.s_addr & mask_blk.s_addr) == (ip_blk.s_addr & mask_blk.s_addr)) || ((ip0.s_addr & mask_blk.s_addr) == (ip_blk.s_addr & mask_blk.s_addr))) {
        struct in_addr ip2;
		if ((ip0.s_addr & mask_blk.s_addr) == (ip_blk.s_addr & mask_blk.s_addr)){
			ip2.s_addr = ip0.s_addr;
		}
		else{
			ip2.s_addr = ip1.s_addr;
		}
		inet_ntop(AF_INET, &(ip2), str, 16);
        printf("[IP blocked] : %s\n", str);
        return 1;
    }
    return 0;

	/****************************************************/
}
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
void sr_handlepacket(struct sr_instance *sr,
					 uint8_t *packet /* lent */,
					 unsigned int len,
					 char *interface /* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

    /*
        We provide local variables used in the reference solution.
        You can add or ignore local variables.
    */
	uint8_t *new_pck;	  /* new packet */
	unsigned int new_len; /* length of new_pck */

	unsigned int len_r; /* length remaining, for validation */
	uint16_t checksum;	/* checksum, for validation */

	struct sr_ethernet_hdr *e_hdr0, *e_hdr; /* Ethernet headers */
	struct sr_ip_hdr *i_hdr0, *i_hdr;		/* IP headers */
	struct sr_arp_hdr *a_hdr0, *a_hdr;		/* ARP headers */
	struct sr_icmp_hdr *ic_hdr0;			/* ICMP header */
	/*struct sr_icmp_t0_hdr *ict0_hdr;		 ICMP type0 header */
	struct sr_icmp_t3_hdr *ict3_hdr;		/* ICMP type3 header */
	struct sr_icmp_t11_hdr *ict11_hdr;		/* ICMP type11 header */

	struct sr_if *ifc;			  /* router interface */
	uint32_t ipaddr;			  /* IP address */
	struct sr_rt *rtentry;		  /* routing table entry */
	struct sr_arpentry *arpentry; /* ARP table entry in ARP cache */
	struct sr_arpreq *arpreq;	  /* request entry in ARP cache */
	struct sr_packet *en_pck;	  /* encapsulated packet in ARP cache */

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

		/* destined to router interface */
		if (ifc != NULL){
			/* with ICMP */
			if (i_hdr0->ip_p == ip_protocol_icmp){
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

					ic_hdr0->icmp_type = 0x00;
					ic_hdr0->icmp_sum = 0;
					ic_hdr0->icmp_sum = cksum(ic_hdr0, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));
					rtentry = sr_findLPMentry(sr->routing_table, i_hdr0->ip_dst);

					if (rtentry != NULL)
					{
						ifc = sr_get_interface(sr, rtentry->interface);
						memcpy(e_hdr0->ether_shost, ifc->addr, ETHER_ADDR_LEN);
						arpentry = sr_arpcache_lookup(&(sr->cache), ipaddr);
						if (arpentry != NULL)
						{
							memcpy(e_hdr0->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
							free(arpentry);
							/* send */
							sr_send_packet(sr, packet, len, rtentry->interface);
						}
						else
						{
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
			/* with TCP or UDP */
			else if ((i_hdr0->ip_p == ip_protocol_tcp) || (i_hdr0->ip_p == ip_protocol_udp))
			{
				/* validation */
				if (len_r + sizeof(struct sr_ip_hdr) < ICMP_DATA_SIZE)
					return;

			/**************** fill in code here ******************/
				/* generate ICMP port unreachable packet */
				new_len = sizeof(struct sr_ethernet_hdr) + 
					  sizeof(struct sr_ip_hdr) + 
					  sizeof(struct sr_icmp_t3_hdr);
				new_pck = (uint8_t *)calloc(1, new_len);

				e_hdr = (struct sr_ethernet_hdr *)new_pck;
				e_hdr->ether_type = htons(ethertype_ip);
    			i_hdr = (struct sr_ip_hdr *)(new_pck + sizeof(struct sr_ethernet_hdr));
    			ict3_hdr = (struct sr_icmp_t3_hdr *)(new_pck + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

				memcpy(i_hdr, i_hdr0, sizeof(struct sr_ip_hdr));
				/*i_hdr->ip_v = 0x4;
				//i_hdr->ip_hl = sizeof(struct sr_ip_hdr) / 4;
				//i_hdr->ip_tos = 0x0;*/
				i_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
				/*i_hdr->ip_id = 0x0;
				//i_hdr->ip_off = htons(IP_DF);*/
				i_hdr->ip_ttl = INIT_TTL;
				i_hdr->ip_p = ip_protocol_icmp;
				i_hdr->ip_src = ifc->ip;
				i_hdr->ip_dst = i_hdr0->ip_src;
				i_hdr->ip_sum = 0;
				i_hdr->ip_sum = cksum(i_hdr, sizeof(struct sr_ip_hdr));

				/* fill ICMP header */
				memcpy(ict3_hdr->data, i_hdr0, ICMP_DATA_SIZE);
				ict3_hdr->icmp_type = 3;
				ict3_hdr->icmp_code = 3;
				ict3_hdr->icmp_sum = 0;
				ict3_hdr->icmp_sum = cksum(ict3_hdr, sizeof(struct sr_icmp_t3_hdr));
				/*//ict3_hdr->unused = 0;
				//ict3_hdr->next_mtu = 0;*/

				rtentry = sr_findLPMentry(sr->routing_table, i_hdr->ip_dst);
				if (rtentry != NULL)
				{
					ifc = sr_get_interface(sr, rtentry->interface);
					memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
					arpentry = sr_arpcache_lookup(&(sr->cache), rtentry->gw.s_addr);
					if (arpentry != NULL)
					{
						/*memcpy(e_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);*/
						memcpy(e_hdr->ether_dhost, e_hdr0->ether_shost, ETHER_ADDR_LEN);
						free(arpentry);
						/* send */
						sr_send_packet(sr, new_pck, new_len, rtentry->interface);
					}
					else
					{
						/* queue */
						arpreq = sr_arpcache_queuereq(&(sr->cache), rtentry->gw.s_addr, new_pck, new_len, rtentry->interface);
						sr_arpcache_handle_arpreq(sr, arpreq);
					}
				}

				/* done */
				free(new_pck);
				return;
			/*****************************************************/
			}
			/* with others */
			else
				return;
		}
		/* destined elsewhere, forward */
		else{
			ifc = sr_get_interface(sr, interface);
			struct in_addr ip_addr;
			ip_addr.s_addr = i_hdr0->ip_dst;

			/* refer routing table */
			rtentry = sr_findLPMentry(sr->routing_table, i_hdr0->ip_dst);



			/* routing table hit */
			if (rtentry != NULL){
				struct in_addr ip_addr1;
				ip_addr1.s_addr = rtentry->gw.s_addr;
				char addr1[20];
				char addr2[20];
				strcpy(addr1,inet_ntoa(ip_addr));
				strcpy(addr2,inet_ntoa(ip_addr1));
				if (strcmp(addr1,addr2) == 0){
				/**************** fill in code here *****************/
					/* check TTL expiration */
					if ((i_hdr0->ip_ttl == 1) || (i_hdr0->ip_ttl == 0)){
						if (len_r + sizeof(struct sr_ip_hdr) < ICMP_DATA_SIZE)
							return;
						new_len = sizeof(struct sr_ethernet_hdr) + 
						sizeof(struct sr_ip_hdr) + 
						sizeof(struct sr_icmp_t11_hdr);
						new_pck = (uint8_t *)calloc(1, new_len);

						e_hdr = (struct sr_ethernet_hdr *)new_pck;
						e_hdr->ether_type = htons(ethertype_ip);
						i_hdr = (struct sr_ip_hdr *)(new_pck + sizeof(struct sr_ethernet_hdr));
						ict11_hdr = (struct sr_icmp_t11_hdr *)(new_pck + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

						memcpy(i_hdr, i_hdr0, sizeof(struct sr_ip_hdr));
						i_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t11_hdr));
						i_hdr->ip_ttl = INIT_TTL;
						i_hdr->ip_p = ip_protocol_icmp;
						i_hdr->ip_src = ifc->ip;
						i_hdr->ip_dst = i_hdr0->ip_src;
						i_hdr->ip_sum = 0;
						i_hdr->ip_sum = cksum(i_hdr, sizeof(struct sr_ip_hdr));

						/* ICMP header */
						memcpy(ict11_hdr->data, i_hdr0, ICMP_DATA_SIZE);
						ict11_hdr->icmp_type = 11;
						ict11_hdr->icmp_code = 0;
						ict11_hdr->icmp_sum = 0;
						ict11_hdr->icmp_sum = cksum(ict11_hdr, sizeof(struct sr_icmp_t3_hdr));
						/*ict3_hdr->unused = 0;
						//ict3_hdr->next_mtu = 0;*/

						rtentry = sr_findLPMentry(sr->routing_table, i_hdr->ip_dst);
						if (rtentry != NULL)
						{
							ifc = sr_get_interface(sr, rtentry->interface);
							memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
							arpentry = sr_arpcache_lookup(&(sr->cache), rtentry->gw.s_addr);
							if (arpentry != NULL)
							{
								/*memcpy(e_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);*/
								memcpy(e_hdr->ether_dhost, e_hdr0->ether_shost, ETHER_ADDR_LEN);
								free(arpentry);
								/* send */
								sr_send_packet(sr, new_pck, new_len, rtentry->interface);
							}
							else
							{
								/* queue */
								arpreq = sr_arpcache_queuereq(&(sr->cache), rtentry->gw.s_addr, new_pck, new_len, rtentry->interface);
								sr_arpcache_handle_arpreq(sr, arpreq);
							}
						}

						/* done */
						free(new_pck);
						return;
					}
					
					/* TTL not expired */
					/* set src MAC addr */

					/* refer ARP table */
					arpentry = sr_arpcache_lookup(&(sr->cache), rtentry->gw.s_addr);

					/* decrement TTL  */
					i_hdr0->ip_ttl -= 1;
					i_hdr0->ip_sum = 0;
					i_hdr0->ip_sum = cksum(i_hdr0, sizeof(struct sr_ip_hdr));

					/* hit */	
					if (arpentry != NULL)
					{
						/* set dst MAC addr */
						memcpy(e_hdr0->ether_shost, sr_get_interface(sr, rtentry->interface)->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
						memcpy(e_hdr0->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);

						/* forward */
						sr_send_packet(sr, packet, len, sr_get_interface(sr, rtentry->interface)->name);

						free(arpentry);
					}
					/* ARP table miss */
					else {
						/* queue */
						arpreq = sr_arpcache_queuereq(&(sr->cache), rtentry->gw.s_addr, packet, len, rtentry->interface);
						sr_arpcache_handle_arpreq(sr, arpreq);
					}
					/* done */
					return;
				}
				else{
					if ((i_hdr0->ip_ttl == 1) || (i_hdr0->ip_ttl == 0)){
						if (len_r + sizeof(struct sr_ip_hdr) < ICMP_DATA_SIZE)
							return;
						new_len = sizeof(struct sr_ethernet_hdr) + 
						sizeof(struct sr_ip_hdr) + 
						sizeof(struct sr_icmp_t11_hdr);
						new_pck = (uint8_t *)calloc(1, new_len);

						e_hdr = (struct sr_ethernet_hdr *)new_pck;
						e_hdr->ether_type = htons(ethertype_ip);
						i_hdr = (struct sr_ip_hdr *)(new_pck + sizeof(struct sr_ethernet_hdr));
						ict11_hdr = (struct sr_icmp_t11_hdr *)(new_pck + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

						memcpy(i_hdr, i_hdr0, sizeof(struct sr_ip_hdr));
						i_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t11_hdr));
						i_hdr->ip_ttl = INIT_TTL;
						i_hdr->ip_p = ip_protocol_icmp;
						i_hdr->ip_src = ifc->ip;
						i_hdr->ip_dst = i_hdr0->ip_src;
						i_hdr->ip_sum = 0;
						i_hdr->ip_sum = cksum(i_hdr, sizeof(struct sr_ip_hdr));

						/* ICMP header */
						memcpy(ict11_hdr->data, i_hdr0, ICMP_DATA_SIZE);
						ict11_hdr->icmp_type = 11;
						ict11_hdr->icmp_code = 0;
						ict11_hdr->icmp_sum = 0;
						ict11_hdr->icmp_sum = cksum(ict11_hdr, sizeof(struct sr_icmp_t3_hdr));
						/*ict3_hdr->unused = 0;
						//ict3_hdr->next_mtu = 0;*/

						rtentry = sr_findLPMentry(sr->routing_table, i_hdr->ip_dst);
						if (rtentry != NULL)
						{
							ifc = sr_get_interface(sr, rtentry->interface);
							memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
							arpentry = sr_arpcache_lookup(&(sr->cache), rtentry->gw.s_addr);
							if (arpentry != NULL)
							{
								/*memcpy(e_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);*/
								memcpy(e_hdr->ether_dhost, e_hdr0->ether_shost, ETHER_ADDR_LEN);
								free(arpentry);
								/* send */
								sr_send_packet(sr, new_pck, new_len, rtentry->interface);
							}
							else
							{
								/* queue */
								arpreq = sr_arpcache_queuereq(&(sr->cache), rtentry->gw.s_addr, new_pck, new_len, rtentry->interface);
								sr_arpcache_handle_arpreq(sr, arpreq);
							}
						}

						/* done */
						free(new_pck);
						return;
					}
					arpreq = sr_arpcache_queuereq(&(sr->cache), i_hdr0->ip_dst, packet, len, rtentry->interface);
					sr_arpcache_handle_arpreq(sr, arpreq);
				}
			/*****************************************************/
			}
			/* routing table miss */
			else{
			/**************** fill in code here *****************/

				/* validation */
				if (len_r + sizeof(struct sr_ip_hdr) < ICMP_DATA_SIZE)
					return;

			/**************** fill in code here ******************/
				/* generate ICMP port unreachable packet */
				new_len = sizeof(struct sr_ethernet_hdr) + 
					  sizeof(struct sr_ip_hdr) + 
					  sizeof(struct sr_icmp_t3_hdr);
				new_pck = (uint8_t *)calloc(1, new_len);
				memset(new_pck, 0, sizeof(uint8_t) * new_len);

				e_hdr = (struct sr_ethernet_hdr *)new_pck;
				e_hdr->ether_type = htons(ethertype_ip);
    			i_hdr = (struct sr_ip_hdr *)(new_pck + sizeof(struct sr_ethernet_hdr));
    			ict3_hdr = (struct sr_icmp_t3_hdr *)(new_pck + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

				
				memcpy(i_hdr, i_hdr0, sizeof(struct sr_ip_hdr));
				i_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
				i_hdr->ip_ttl = INIT_TTL;
				i_hdr->ip_p = ip_protocol_icmp;
				i_hdr->ip_src = (uint32_t)ifc->ip;
				i_hdr->ip_dst = (uint32_t)i_hdr0->ip_src;
				
				i_hdr->ip_sum = 0;
				i_hdr->ip_sum = cksum(i_hdr, sizeof(struct sr_ip_hdr));

				memcpy(ict3_hdr->data, i_hdr0, ICMP_DATA_SIZE);
				ict3_hdr->icmp_type = 3;
				ict3_hdr->icmp_code = 0;
				ict3_hdr->icmp_sum = 0; 
				
				ict3_hdr->icmp_sum = cksum(ict3_hdr, sizeof(struct sr_icmp_t3_hdr));
				/*ict3_hdr->unused = 0;
				ict3_hdr->next_mtu = 0;*/

				rtentry = sr_findLPMentry(sr->routing_table, i_hdr->ip_dst);
				if (rtentry != NULL)
				{
					ifc = sr_get_interface(sr, rtentry->interface);
					memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
					arpentry = sr_arpcache_lookup(&(sr->cache), rtentry->gw.s_addr);
					if (arpentry != NULL)
					{
						/*memcpy(e_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);*/
						memcpy(e_hdr->ether_dhost, e_hdr0->ether_shost, ETHER_ADDR_LEN);
						free(arpentry);
						/* send */
						sr_send_packet(sr, new_pck, new_len, rtentry->interface);
					}
					else
					{
						/* queue */
						arpreq = sr_arpcache_queuereq(&(sr->cache), rtentry->gw.s_addr, new_pck, new_len, rtentry->interface);
						sr_arpcache_handle_arpreq(sr, arpreq);
					}
				}

				/* done */
				free(new_pck);
				return;


			/*****************************************************/
			}
		}
	}
	/* ARP packet arrived */
	else if (e_hdr0->ether_type == htons(ethertype_arp)){
		/* validation */
		if (len_r < sizeof(struct sr_arp_hdr))
			return;

		a_hdr0 = (struct sr_arp_hdr *)(((uint8_t *)e_hdr0) + sizeof(struct sr_ethernet_hdr)); /* a_hdr0 set */

		/* destined to me */
		ifc = sr_get_interface(sr, interface);
		if (a_hdr0->ar_tip == ifc->ip){
			/* request code */
			if (a_hdr0->ar_op == htons(arp_op_request)){
			/**************** fill in code here *****************/	
				/* generate reply */
				uint8_t *arp_reply = (uint8_t *) malloc(len);
				memset(arp_reply, 0, len * sizeof(uint8_t));

				e_hdr = (struct sr_ethernet_hdr *)arp_reply;
				a_hdr = (struct sr_arp_hdr *)(arp_reply + sizeof(sr_ethernet_hdr_t));


				/* fill Ethernet header */
				memcpy(e_hdr->ether_dhost, e_hdr0->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
				memcpy(e_hdr->ether_shost, ifc->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
				e_hdr->ether_type = htons(ethertype_arp);

				memcpy(a_hdr, a_hdr0, sizeof(sr_arp_hdr_t));
				/* fill ARP header 
				reply_arp_header->ar_hrd = htons(arp_hrd_ethernet);
				reply_arp_header->ar_pro = htons(ethertype_ip);
				reply_arp_header->ar_hln = ETHER_ADDR_LEN;
				reply_arp_header->ar_pln = sizeof(uint32_t);*/
				a_hdr->ar_op = htons(arp_op_reply);
				memcpy(a_hdr->ar_sha, ifc->addr, ETHER_ADDR_LEN);
				a_hdr->ar_sip = ifc->ip;
				memcpy(a_hdr->ar_tha, e_hdr0->ether_shost, ETHER_ADDR_LEN);
				a_hdr->ar_tip = a_hdr0->ar_sip;

				/* send */
				sr_send_packet(sr, arp_reply, len, interface);
				
				/* done */
				free(arp_reply);
				return;
			/*****************************************************/
			}

			/* reply code */
			else if (a_hdr0->ar_op == htons(arp_op_reply)){
			/**************** fill in code here *****************/
				/* pass info to ARP cache */
				struct sr_arpreq *request = sr_arpcache_insert(&(sr->cache), a_hdr0->ar_sha, a_hdr0->ar_sip);

				/* pending request exist */
				if (request != NULL) {
					/* go through all waiting packets */
					en_pck = request->packets;
					while (en_pck != NULL) {
						/* set dst MAC addr */
						uint8_t *send_packet = en_pck->buf;
						e_hdr = (struct sr_ethernet_hdr *)(send_packet);
						memcpy(e_hdr->ether_dhost, a_hdr0->ar_sha, sizeof(uint8_t) * ETHER_ADDR_LEN);
						memcpy(e_hdr->ether_shost, ifc->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
						/* send */

						sr_send_packet(sr, send_packet, en_pck->len, interface);
						
						en_pck = en_pck->next;
					}

					/* done */
					sr_arpreq_destroy(&(sr->cache), request);
				}
			/*****************************************************/
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

} /* end sr_ForwardPacket */

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
