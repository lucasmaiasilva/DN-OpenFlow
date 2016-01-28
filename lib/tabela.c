#include "tabela.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <stdint.h>

typedef struct l {
    uint8_t url[30];
    //uint8_t ip[4];
    uint32_t ip;
    struct l* prox;
}linha;


typedef struct{
    linha *primeira;
    linha *ultima;
}tabela;



int vazia(tabela *tab){
    return (tab->primeira==tab->ultima);
}

void inicializa(tabela *tab){
    tab->primeira=(linha*)malloc(sizeof(linha));
    tab->ultima=tab->primeira;
    tab->primeira->prox=NULL;
}

void adicionaLinha(tabela* tab,uint8_t url[30],uint32_t ip){
    tab->ultima->prox=(linha*)malloc(sizeof(linha));
    memcpy(tab->ultima->url,url,30);
    //memcpy(tab->ultima->ip,ip,4);
    tab->ultima->ip=ip;
    tab->ultima=tab->ultima->prox;
    tab->ultima->prox=NULL;
}

void imprime(tabela *tab,FILE *arquivo){
    linha* aux;
    aux=tab->primeira;
    while (aux->prox!=NULL) {
        fprintf(arquivo,"%s %x \n",aux->url,aux->ip);
        aux=aux->prox;
    }
}



