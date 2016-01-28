/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 * 
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */
#include <config.h>
#include <sys/types.h>
#include "flow.h"
#include <inttypes.h>
#include <netinet/in.h>
#include <string.h>
#include "hash.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "random.h"

#include "vlog.h"

#include "tabela.h"
#define THIS_MODULE VLM_flow

//comeca a esculhambacao


void imprimeDNS(FILE* arquivo, struct dns_header *dns_h, struct dns *d,struct dns_question *dns_q,struct dns_ans_header *dns_a){

  fprintf(arquivo,"id transacao:%d\n",htons(dns_h->id));
  fprintf(arquivo,"  quantidade de queries:%d\n",htons(dns_h->n_queries));
  fprintf(arquivo,"  quantidade de respost:%d\n",htons(dns_h->n_answers));
  fprintf(arquivo,"  quantidade de aut_rec:%d\n",htons(dns_h->n_aut_rec));
  fprintf(arquivo,"  quantidade de add_rec:%d\n",htons(dns_h->a_rec_pkt));
  fprintf(arquivo,"  nome do dominio      :%s\n",d->dns_name);
  fprintf(arquivo,"  tipo                 :%d\n",dns_q->type);
  fprintf(arquivo,"  classe               :%d\n",htons(dns_q->classe));
  //fprintf(arquivo,"  nome                 :%d\n",htons(dns_a->name));
  fprintf(arquivo,"  tipo                 :%d\n",htons(dns_a->type));
  fprintf(arquivo,"  classe               :%d\n",dns_a->classe);
  fprintf(arquivo,"  ttl                  :%d\n",dns_a->ttl);
  fprintf(arquivo,"  data length          :%d\n",dns_a->data_len);
}

void adiciona(struct tabela tab[],uint8_t url[30], uint32_t ip){
	memcpy(tab[tab->size].url,url,30);
	tab[tab->size].ip=ip;
	tab->size++;	

}

void imprimeTabela(struct tabela tab[],FILE *arquivo){
	int i = 0;
	for(i=0;i<tab->size;i++){
	  fprintf(arquivo,"url %s ip %x\n",tab[i].url,tab[i].ip);
	}
	fprintf(arquivo,"tamanho %d\n",tab->size);

}

int tabela_cmp(const void *v1, const void *v2){

	const struct tabela *t1 = v1;
	const struct tabela *t2 = v2;
	return strcmp(t1->url,t2->url);

}

int tabelaCmpIp(const void *v1, const void *v2){
	const struct tabela *t1 = v1;
	const struct tabela *t2 = v2;
	
	if (t1->ip == t2->ip)
                return 0;
        if(t1->ip > t2->ip)
                return 1;
        if(t1->ip < t2->ip)
                return -1;
	
}


uint8_t* buscaIp(struct tabela tab[],uint32_t ip){
	struct tabela item, *resultado;
        item.ip=ip;
	qsort(tab,tab->size,sizeof(struct tabela),tabelaCmpIp);
        resultado = bsearch (&item, tab, tab->size, sizeof (struct tabela),
                    tabelaCmpIp);
        if (resultado)
		return resultado->url;
        else
		return NULL;
}

void busca(struct tabela tab[],uint8_t url[30]){
	struct tabela item, *resultado;
	memcpy(item.url,url,30);
  	resultado = bsearch (&item, tab, tab->size, sizeof (struct tabela),
                    tabela_cmp);
  	if (resultado)
    		printf("Encontrado %s %x\n",resultado->url,resultado->ip);
  	else
    		printf ("Nao foi possivel encontrar %s.\n", url);

}



static struct arp_header *
pull_arp(struct ofpbuf *packet)
{
    if (packet->size >= ARP_ETH_HEADER_LEN) {
        struct arp_eth_header *arp = packet->data;
        return ofpbuf_pull(packet, ARP_ETH_HEADER_LEN);
    }
    return NULL;
}

static struct ip_header *
pull_ip(struct ofpbuf *packet)
{
    if (packet->size >= IP_HEADER_LEN) {
        struct ip_header *ip = packet->data;
        int ip_len = IP_IHL(ip->ip_ihl_ver) * 4;
        if (ip_len >= IP_HEADER_LEN && packet->size >= ip_len) {
            return ofpbuf_pull(packet, ip_len);
        }
    }
    return NULL;
}

static struct tcp_header *
pull_tcp(struct ofpbuf *packet) 
{
    if (packet->size >= TCP_HEADER_LEN) {
        struct tcp_header *tcp = packet->data;
        int tcp_len = TCP_OFFSET(tcp->tcp_ctl) * 4;
        if (tcp_len >= TCP_HEADER_LEN && packet->size >= tcp_len) {
            return ofpbuf_pull(packet, tcp_len);
        }
    }
    return NULL;
}

static struct udp_header *
pull_udp(struct ofpbuf *packet) 
{
    return ofpbuf_try_pull(packet, UDP_HEADER_LEN);
}

static struct icmp_header *
pull_icmp(struct ofpbuf *packet) 
{
    return ofpbuf_try_pull(packet, ICMP_HEADER_LEN);
}

static struct eth_header *
pull_eth(struct ofpbuf *packet) 
{
    return ofpbuf_try_pull(packet, ETH_HEADER_LEN);
}

static struct vlan_header *
pull_vlan(struct ofpbuf *packet)
{
    return ofpbuf_try_pull(packet, VLAN_HEADER_LEN);
}



/* Returns 1 if 'packet' is an IP fragment, 0 otherwise. */
int
flow_extract(struct ofpbuf *packet, uint16_t in_port, struct flow *flow)
{
    //criacao da tabela para armazenar url e ips
    static struct tabela tab[150];
    
    struct ofpbuf b = *packet;
    struct eth_header *eth;
    int retval = 0;

    memset(flow, 0, sizeof *flow);
    flow->dl_vlan = htons(OFP_VLAN_NONE);
    flow->in_port = htons(in_port);
    

    packet->l2 = b.data;
    packet->l3 = NULL;
    packet->l4 = NULL;
    packet->l7 = NULL;

    eth = pull_eth(&b);
    if (eth) {
        if (ntohs(eth->eth_type) >= OFP_DL_TYPE_ETH2_CUTOFF) {
            /* This is an Ethernet II frame */
            flow->dl_type = eth->eth_type;
        } else {
            /* This is an 802.2 frame */
            struct llc_header *llc = ofpbuf_at(&b, 0, sizeof *llc);
            struct snap_header *snap = ofpbuf_at(&b, sizeof *llc,
                                                 sizeof *snap);
            if (llc == NULL) {
                return 0;
            }
            if (snap
                && llc->llc_dsap == LLC_DSAP_SNAP
                && llc->llc_ssap == LLC_SSAP_SNAP
                && llc->llc_cntl == LLC_CNTL_SNAP
                && !memcmp(snap->snap_org, SNAP_ORG_ETHERNET,
                           sizeof snap->snap_org)) {
                flow->dl_type = snap->snap_type;
                ofpbuf_pull(&b, LLC_SNAP_HEADER_LEN);
            } else {
                flow->dl_type = htons(OFP_DL_TYPE_NOT_ETH_TYPE);
                ofpbuf_pull(&b, sizeof(struct llc_header));
            }
        }

        /* Check for a VLAN tag */
        if (flow->dl_type == htons(ETH_TYPE_VLAN)) {
            struct vlan_header *vh = pull_vlan(&b);
            if (vh) {
                flow->dl_type = vh->vlan_next_type;
                flow->dl_vlan = vh->vlan_tci & htons(VLAN_VID_MASK);
                flow->dl_vlan_pcp = (uint8_t)((ntohs(vh->vlan_tci) >> VLAN_PCP_SHIFT)
                                               & VLAN_PCP_BITMASK);
            }
        }
        memcpy(flow->dl_src, eth->eth_src, ETH_ADDR_LEN);
        memcpy(flow->dl_dst, eth->eth_dst, ETH_ADDR_LEN);

        packet->l3 = b.data;
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            const struct ip_header *nh = pull_ip(&b);
            if (nh) {
                flow->nw_tos = nh->ip_tos & 0xfc;
                flow->nw_proto = nh->ip_proto;
                flow->nw_src = nh->ip_src;
                flow->nw_dst = nh->ip_dst;
                packet->l4 = b.data;
                if (!IP_IS_FRAGMENT(nh->ip_frag_off)) {

		     //[alteracao] atribuicao de nomes de dominio a pacotes que possuem IP address
		     uint8_t *url_tmp;
                     //url_tmp=buscaIp(tab,flow->nw_dst);
                     //if(url_tmp!=NULL)
                     //  memcpy(flow->URL,url_tmp,30);
                     url_tmp=buscaIp(tab,flow->nw_src);
                     if(url_tmp!=NULL)
                       memcpy(flow->URL,url_tmp,30);


                    if (flow->nw_proto == IP_TYPE_TCP) {
                        const struct tcp_header *tcp = pull_tcp(&b);
                        if (tcp) {
                            flow->tp_src = tcp->tcp_src;
                            flow->tp_dst = tcp->tcp_dst;
                            packet->l7 = b.data;
 
		            //if(flow->tp_src==80){
  		     	    //uint8_t *url_tmp;
                            //url_tmp=buscaIp(tab,flow->nw_dst);
                            //if(url_tmp!=NULL)
                              //memcpy(flow->URL,url_tmp,30);
                            //url_tmp=buscaIp(tab,flow->nw_src);
                            //if(url_tmp!=NULL)
                             // memcpy(flow->URL,url_tmp,30);
			    //}

			    //[gambeta]
			    //int indice;
			    //static int contador = 0;
			    //char nombre[30];
			    //sprintf(nombre,"saida_%d.txt",contador);
			    //FILE *arquivo;
		            //arquivo=fopen(nombre,"w+");

			    //void *string=b.data;
			    //fprintf(arquivo,"%s",string);
			    //uint8_t *url_tmp;
			    //url_tmp=buscaIp(tab,flow->nw_dst);
			    //if(url_tmp!=NULL)
			    //   memcpy(flow->URL,url_tmp,30);
			    //url_tmp=buscaIp(tab,flow->nw_src);
                            //if(url_tmp!=NULL)
                            //   memcpy(flow->URL,url_tmp,30);
			    //fprintf(arquivo,"\n flow->URL : %s \n",flow->URL);
			    //fprintf(arquivo,"\nip dst:%x ip src:%x pt dst:%x pt src:%x url ip_dst %s url ip_src %s\n",flow->nw_dst,flow->nw_src,htons(flow->tp_dst),htons(flow->tp_src),buscaIp(tab,flow->nw_dst),buscaIp(tab,flow->nw_src));
			    //imprimeTabela(tab,arquivo);
		            //fclose(arquivo);
			    //contador++;
			    
                        } else {
                            /* Avoid tricking other code into thinking that
                             * this packet has an L4 header. */
                            flow->nw_proto = 0;
                        }
                    } else if (flow->nw_proto == IP_TYPE_UDP) {
                        const struct udp_header *udp = pull_udp(&b);
                        if (udp) {
                            flow->tp_src = udp->udp_src;
                            flow->tp_dst = udp->udp_dst;
                            packet->l7 = b.data;
			    
		            //[alteracao] parsing do dns do pacote para fluxo

			    if (( htons(udp->udp_src) == 0x35 ) || ( htons(udp->udp_dst) == 0x35 )){
				//FILE *lucas;
				//static int contador1=0;
				//char nome[20];
				//sprintf(nome,"dns_%d.txt",contador1);
				//lucas=fopen(nome,"w+");
				uint8_t URL_TEMP[30];
				int i=0;
				
			        const struct dns_header *dns = ofpbuf_pull(&b,12);
			
				uint8_t *dns_payload = b.data;
                                //fprintf(lucas,"Tamanho b.size%d  Tamanho udp_len%d  Qtde de respostas%d\n",b.size,htons(udp->udp_len),htons(dns->n_answers));

		 	        //for(i=0;i<b.size;i++)
				//	fprintf(lucas,"%02x ", dns_payload[i] );
				//fprintf(lucas,"\n");
				
				/*
				if(b.next!=NULL){
				dns_payload = b.next->data;
				for(i=0;i<b.next->size;i++)
					fprintf(lucas,"%02X ",dns_payload[i]);
				fprintf(lucas,"\n");
				}*/
				
				memset(URL_TEMP,'\0',30);
			        //extrai URL ( nome de dominio )
				
			
				for(i=1;dns_payload[i]!='\0';i++){
					if(dns_payload[i]<32)
						URL_TEMP[i-1] = 0x2e;
					else
						URL_TEMP[i-1]=dns_payload[i];
				}			
				int dns_name_len = i;	
				const struct dns *d_name = URL_TEMP;
				uint8_t *lixo = ofpbuf_pull(&b,dns_name_len);
				const struct dns_question *dq = ofpbuf_pull(&b,4);

				uint8_t ip_addr[4];
				memset(ip_addr,'\0',4);
				uint32_t ip_addr_2;
			        int j = 0;	

				//verifica se existem respostas no pacote DNS
				
				if(htons(dns->n_answers)>0){
				  lixo = ofpbuf_pull(&b,1);
				  for(i=0;i<(htons(dns->n_answers))&&b.size>=16;i++){
		
					lixo = ofpbuf_pull(&b,2);
                                        const struct dns_ans_header *ans_h = ofpbuf_pull(&b,10);
					//fprintf(lucas,"tipo: %d\n",htons(ans_h->type));
					if(htons(ans_h->type)==1&&b.size>=4){
					   
					   memcpy(ip_addr,ofpbuf_pull(&b,4),4);
				   	   //testeip_addr_2 = ip_addr[0] << 24 | ip_addr[1] << 16 | ip_addr[2] << 8 | ip_addr[3];
				    	   ip_addr_2 = ip_addr[3]<<24 | ip_addr[2] <<16 | ip_addr[1] << 8 | ip_addr[0];
					   //fprintf(lucas,"\n%d.%d.%d.%d",ip_addr[0],ip_addr[1],ip_addr[2],ip_addr[3]);
                                           //fprintf(lucas," - %02x.%02x.%02x.%02x - %x\n",ip_addr[0],ip_addr[1],ip_addr[2],ip_addr[3],ip_addr_2);
					   if(buscaIp(tab,ip_addr_2)==NULL){
					   	adiciona(tab,URL_TEMP,ip_addr_2);
					        //qsort(tab,tab->size,sizeof(struct tabela),tabelaCmpIp);
					   }

				        }
					if(htons(ans_h->type)==5){
					   //fprintf(lucas,"data_len:%d\n",htons(ans_h->data_len));
					   lixo=ofpbuf_pull(&b,htons(ans_h->data_len));
					}
				    }
				}
				
				//imprimeDNS(lucas,dns,d_name,dq,dns_ans);
	
				//memcpy(flow->URL,URL_TEMP,30);
				//imprimeTabela(tab,lucas);
				//fclose(lucas);
				//contador1++;

			    }
                        } else {
                            /* Avoid tricking other code into thinking that
                             * this packet has an L4 header. */
                            flow->nw_proto = 0;
                        }
                    } else if (flow->nw_proto == IP_TYPE_ICMP) {
                        const struct icmp_header *icmp = pull_icmp(&b);
                        if (icmp) {
                            flow->icmp_type = htons(icmp->icmp_type);
                            flow->icmp_code = htons(icmp->icmp_code);
                            packet->l7 = b.data;
                        } else {
                            /* Avoid tricking other code into thinking that
                             * this packet has an L4 header. */
                            flow->nw_proto = 0;
                        }
                    }
                } else {
                    retval = 1;
                }
            }
        } else if (flow->dl_type == htons(ETH_TYPE_ARP)) {
            const struct arp_eth_header *arp = pull_arp(&b);
            if (arp) {
                if (arp->ar_pro == htons(ARP_PRO_IP) && arp->ar_pln == IP_ADDR_LEN) {
                    flow->nw_src = arp->ar_spa;
                    flow->nw_dst = arp->ar_tpa;
                }
                flow->nw_proto = ntohs(arp->ar_op) & 0xff;
            }
        }
    }
    return retval;
}

void
flow_fill_match(struct ofp_match *to, const struct flow *from,
                uint32_t wildcards)
{
    to->wildcards = htonl(wildcards);
    to->in_port = from->in_port;
    to->dl_vlan = from->dl_vlan;
    memcpy(to->dl_src, from->dl_src, ETH_ADDR_LEN);
    memcpy(to->dl_dst, from->dl_dst, ETH_ADDR_LEN);
    //[alteracao]
    memcpy(to->URL,from->URL,30);
    to->dl_type = from->dl_type;
    to->nw_tos = from->nw_tos;
    to->nw_proto = from->nw_proto;
    to->nw_src = from->nw_src;
    to->nw_dst = from->nw_dst;
    to->tp_src = from->tp_src;
    to->tp_dst = from->tp_dst;
    to->dl_vlan_pcp = from->dl_vlan_pcp;
}

void
flow_print(FILE *stream, const struct flow *flow) 
{
    fprintf(stream,
            "port %04x vlan-vid %04x vlan-pcp %02x src-mac "ETH_ADDR_FMT" "
            "dst-mac "ETH_ADDR_FMT" frm-type %04x ip-tos %02x ip-proto %02x "
            "src-ip "IP_FMT" dst-ip "IP_FMT" tp-src %d tp-dst %d",
            ntohs(flow->in_port), ntohs(flow->dl_vlan), flow->dl_vlan_pcp,
            ETH_ADDR_ARGS(flow->dl_src), ETH_ADDR_ARGS(flow->dl_dst),
            ntohs(flow->dl_type),
            flow->nw_tos, flow->nw_proto,
            IP_ARGS(&flow->nw_src), IP_ARGS(&flow->nw_dst),
            ntohs(flow->tp_src), ntohs(flow->tp_dst));
}
