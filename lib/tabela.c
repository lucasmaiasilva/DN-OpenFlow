#include "tabela.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <stdint.h>

/*
typedef struct l {
    uint8_t dn[32];
    //uint8_t ip[4];
    uint32_t ip;
    struct l* prox;
}linha;


typedef struct{
    linha *primeira;
    linha *ultima;
}tabela;*/


void adiciona(struct tabela tab[],uint8_t dn[32], uint32_t ip){
	memcpy(tab[tab->size].dn,dn,32);
	tab[tab->size].ip=ip;
	tab->size++;

}

void imprimeTabela(struct tabela tab[]){
  FILE *arquivo;
  arquivo=fopen("tabela","w+");


	int i = 0;
	for(i=0;i<tab->size;i++){
	  fprintf(arquivo,"dn %s ip %x\n",tab[i].dn,tab[i].ip);
	}
	fprintf(arquivo,"tamanho %d\n",tab->size);
  fclose(arquivo);

}

int tabela_cmp(const void *v1, const void *v2){

	const struct tabela *t1 = v1;
	const struct tabela *t2 = v2;
	return strcmp(t1->dn,t2->dn);

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
		return resultado->dn;
        else
		return NULL;
}

void busca(struct tabela tab[],uint8_t dn[32]){
	struct tabela item, *resultado;
	memcpy(item.dn,dn,32);
  	resultado = bsearch (&item, tab, tab->size, sizeof (struct tabela),
                    tabela_cmp);
  	if (resultado)
    		printf("Encontrado %s %x\n",resultado->dn,resultado->ip);
  	else
    		printf ("Nao foi possivel encontrar %s.\n", dn);

}


int vazia(tabela *tab){
    return (tab->primeira==tab->ultima);
}

void inicializa(tabela *tab){
    tab->primeira=(linha*)malloc(sizeof(linha));
    tab->ultima=tab->primeira;
    tab->primeira->prox=NULL;
}

void adicionaLinha(tabela* tab,uint8_t dn[32],uint32_t ip){
    tab->ultima->prox=(linha*)malloc(sizeof(linha));
    memcpy(tab->ultima->dn,dn,32);
    //memcpy(tab->ultima->ip,ip,4);
    tab->ultima->ip=ip;
    tab->ultima=tab->ultima->prox;
    tab->ultima->prox=NULL;
}

void imprime(tabela *tab,FILE *arquivo){
    linha* aux;
    aux=tab->primeira;
    while (aux->prox!=NULL) {
        fprintf(arquivo,"%s %x \n",aux->dn,aux->ip);
        aux=aux->prox;
    }
}

/*remove item da tabela*/


/**TO DO - FUNCOES DO TTL*/




/*atualiza ttl*/
/*seta ttl*/
