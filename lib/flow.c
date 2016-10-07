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
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include "hash.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "random.h"

#include "vlog.h"

#include "tabela.h"

#define THIS_MODULE VLM_flow

//comeca a esculhambacao...

static int tamanho = 0;
static struct tabela tab[15000];


void handle(int sig){
  int i=0;
  for(i=0;i<tamanho;i++){
    tab[i].ttl--;
    if(tab[i].ttl==0){
      /*remove registro*/
      tab[i].ip = tab[tamanho-1].ip;
      memcpy(tab[i].dn, tab[tamanho-1].dn,32);
      tab[i].ttl = tab[tamanho-1].ttl;
      tamanho--;
    }
  }
  alarm(1);
}

void atualizaTTL(struct tabela tab[]){

}


void apaga(struct tabela tab[]){
  int i;
  for(i=0;i<tamanho;i++){
    if(tab[i].ttl==0){
      tab[i].ip = tab[tamanho-1].ip;
      memcpy(tab[i].dn, tab[tamanho-1].dn,32);
      tab[i].ttl = tab[tamanho-1].ttl;
      tamanho--;
    }
  }
}

void adiciona(struct tabela tab[],uint8_t dn[32], uint32_t ip,uint32_t ttl){
  memcpy(tab[tamanho].dn,dn,32);
  tab[tamanho].ip=ip;
  tab[tamanho].ttl=ttl;
  tab[tamanho].ttl_old=ttl;
  tamanho++;
}

void imprimeTabela(struct tabela tab[]){
  FILE *arquivo;
  char *ipv4;
  struct in_addr *ptr;
  int i = 0;
  arquivo=fopen("tabela","w+");
  for(i=0;i<tamanho;i++){
    ptr=&tab[i].ip;
    fprintf(arquivo,"dn - %s ip - %x ipv4 - %s ttl - %d\n",tab[i].dn,tab[i].ip,inet_ntoa(*ptr),tab[i].ttl);
  }
  fprintf(arquivo,"tamanho %d\n",tamanho);
  fclose(arquivo);

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
	qsort(tab,tamanho,sizeof(struct tabela),tabelaCmpIp);
  resultado = bsearch (&item, tab, tamanho, sizeof (struct tabela),tabelaCmpIp);
  if (resultado){
    resultado->ttl=resultado->ttl_old;
	  return resultado->dn;
  }
  else{
    return NULL;
  }
}


int busca(struct tabela tab[],uint32_t ip){
	struct tabela item, *resultado;
  item.ip=ip;
	qsort(tab,tamanho,sizeof(struct tabela),tabelaCmpIp);
  resultado = bsearch (&item, tab, tamanho, sizeof (struct tabela),tabelaCmpIp);
  if (resultado)
	  return 1;
  else
  	return 0;
}


/*
void print_dns(struct dns_header *dns,uint8_t *name, struct dns_question *dns_q, struct dns_ans_header *dns_a){
  FILE *arquivo;
  char nome[15];
  static int cont=0;
  sprintf(nome,"teste%d.txt",cont++);
  arquivo=fopen(nome,"w+");
  fprintf(arquivo, "DNS Header\n");
  fprintf(arquivo,"[dns->id]        %x\n",ntohs(dns->id));
  fprintf(arquivo,"[dns->flags]     %x\n",ntohs(dns->flags));
  fprintf(arquivo,"[dns->n_queries] %x\n",ntohs(dns->n_queries));
  fprintf(arquivo,"[dns->n_answers] %x\n",ntohs(dns->n_answers));
  fprintf(arquivo,"[dns->n_aut_rec] %x\n",ntohs(dns->n_aut_rec));
  fprintf(arquivo,"[dns->n_rec_pkt] %x\n",ntohs(dns->n_rec_pkt));

  fprintf(arquivo, "\n");
  fprintf(arquivo, "DNS Question Name\n");
  fprintf(arquivo,"[Name]         %s\n",name);
  fprintf(arquivo,"[dns_q->type]  %x\n",ntohs(dns_q->type));
  fprintf(arquivo,"[dns_q->class] %x\n",ntohs(dns_q->class));

  fprintf(arquivo, "\n");

  fprintf(arquivo, "DNS Answer\n");
  fprintf(arquivo,"[dns_a->type]     %x\n",ntohs(dns_a->type));
  fprintf(arquivo,"[dns_a->class]    %x\n",ntohs(dns_a->class));
  fprintf(arquivo,"[dns_a->ttl]      %x\n",ntohl(dns_a->ttl));
  fprintf(arquivo,"[dns_a->data_len] %x\n",ntohs(dns_a->data_len));

  fprintf(arquivo, "\n");
  fclose(arquivo);
}*/


void parse_dns_name(struct ofpbuf *b, uint8_t name[]){

  uint8_t *pull=0x1;
  memset(name,'\0',512);
  pull = ofpbuf_try_pull(b,1);
  if(pull==NULL){
    return;
  }
  /*trata labels*/
  if(pull[0]==0xc0){
    /*TO-DO a label parser*/
    pull = ofpbuf_try_pull(b,1);
    if(pull==NULL){
      return;
    }
  }
  else{
    while(pull[0]!=0x0){
      pull=ofpbuf_try_pull(b,1);
      if(pull==NULL){
        return;
      }
      if(pull[0]<0x20&&pull[0]>0x0){
        name[strlen(name)]=0x2e;
      }else{
        memcpy(name+strlen(name),pull,1);
      }
    }
  }
}

void dns_parser(struct ofpbuf b,struct tabela tab[]){
  uint8_t name[512];
  uint8_t aux[1024];
  uint32_t *auxiliar;
  int i=0;
  char *ipv4;
  struct in_addr *ptr;

  /*retira cabecalho do pacote dns 12 bytes fixos do cabecalho*/
  const struct dns_header *dns = ofpbuf_try_pull(&b,12);
  /*trata erro do servidor*/
  if((ntohs(dns->flags)&0x2)==0x2){
    return;
  }

  /*trata o nome da consulta dns*/
  parse_dns_name(&b,&name);
  /*retira os dados da questao DNS*/
  const struct dns_question *dns_q = ofpbuf_try_pull(&b,4);
  for(i=0;i<ntohs(dns->n_answers);i++){
    parse_dns_name(&b,&aux);
    const struct dns_ans_header *dns_a = ofpbuf_try_pull(&b,10);
    if(dns_a==NULL){
      return;
    }
    auxiliar = ofpbuf_try_pull(&b,ntohs(dns_a->data_len));
    if (auxiliar==NULL){
      return;
    }
    if((ntohs(dns_a->type)==1)&&(ntohs(dns_a->class)==1)){
      ptr=auxiliar;
      ipv4 = inet_ntoa(*ptr);
      if(busca(tab,*auxiliar)==0){
        adiciona(tab,name,*auxiliar,ntohl(dns_a->ttl));
      }
    }
  }

  /*authority ns*/
  for(i=0;i<ntohs(dns->n_aut_rec);i++){
    parse_dns_name(&b,&aux);
    const struct dns_ans_header *dns_a = ofpbuf_try_pull(&b,10);
    if(dns_a==NULL){
      return;
    }
    auxiliar = ofpbuf_try_pull(&b,ntohs(dns_a->data_len));
    if (auxiliar==NULL){
      return;
    }
    if((ntohs(dns_a->type)==1)&&(ntohs(dns_a->class)==1)){
      ptr=auxiliar;
      ipv4 = inet_ntoa(*ptr);
      if(busca(tab,*auxiliar)==0){
        adiciona(tab,name,*auxiliar,ntohl(dns_a->ttl));
      }
    }
  }

  /*additional records*/

  for(i=0;i<ntohs(dns->n_rec_pkt);i++){
    parse_dns_name(&b,&aux);
    const struct dns_ans_header *dns_a  = ofpbuf_try_pull(&b,10);
    if(dns_a==NULL){
      return;
    }
    auxiliar = ofpbuf_try_pull(&b,ntohs(dns_a->data_len));
    if (auxiliar==NULL){
      return;
    }
    if((ntohs(dns_a->type)==1)&&(ntohs(dns_a->class)==1)){
      ptr=auxiliar;
      ipv4 = inet_ntoa(*ptr);
      if(busca(tab,*auxiliar)==0){
        adiciona(tab,name,*auxiliar,ntohl(dns_a->ttl));
      }
    }
  }
  //print_dns(dns,name,dns_q,dns_a1);
  //imprimeTabela(tab);
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
    //static struct tabela tab[15000];
    struct ofpbuf b = *packet;
    /*trata o ttl*/
    signal(SIGALRM,handle);
    alarm(1);


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
		                 uint8_t *dn_tmp;
                     dn_tmp=buscaIp(tab,flow->nw_dst);
                     if(dn_tmp!=NULL){
                          memcpy(flow->dn_dst,dn_tmp,32);
                     }
                     dn_tmp=buscaIp(tab,flow->nw_src);
                     if(dn_tmp!=NULL){
                          memcpy(flow->dn_src,dn_tmp,32);
                     }


                    if (flow->nw_proto == IP_TYPE_TCP) {
                        const struct tcp_header *tcp = pull_tcp(&b);
                        if (tcp) {
                            flow->tp_src = tcp->tcp_src;
                            flow->tp_dst = tcp->tcp_dst;
                            packet->l7 = b.data;

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

		                        //[alteracao] Parser DNS
			                      if (( ntohs(udp->udp_src) == 0x35 ) ){
                              dns_parser(b,tab);

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
    memcpy(to->dn_src,from->dn_src,32);
    memcpy(to->dn_dst,from->dn_dst,32);
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
