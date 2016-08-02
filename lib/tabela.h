#include <stdlib.h>


struct tabela{
	uint8_t dn[32];
	uint32_t ip;
	size_t size;
	uint8_t ttl;
};


void adiciona(struct tabela tab[],uint8_t dn[32], uint32_t ip);

void imprimeTabela(struct tabela tab[]);

int tabela_cmp(const void *v1, const void *v2);

int tabelaCmpIp(const void *v1, const void *v2);

uint8_t* buscaIp(struct tabela tab[],uint32_t ip);

void busca(struct tabela tab[],uint8_t dn[32]);

/*
int vazia(tabela *tab);

void inicializa(tabela *tab);

void adicionaLinha(tabela* tab,uint8_t dn[32],uint32_t ip);

void imprime(tabela *tab,FILE *arquivo);*/
