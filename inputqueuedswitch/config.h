#ifndef CONFIG_H
	#define CONFIG_H

	#define SIZE_DIVIDER 4 //threshold para send (tamanho ocupado do buffer)
	#define SEND_TIMEOUT 0.0001 //timeout sem sends
	#define SEND_THRESHOLD_0 0.5 //probabilidade máxima para que ainda seja interessante chamar send
	#define MAXVAL_FORWARDINGMAP ~((unsigned int) 0) //utilizado na atualização das estatísticas
	#define UPDATE_STATS 5 //atualiza as estatísticas apenas de 5 em 5 quadros
	#define TOGGLE_PROBABILITY 3 //% probabilidade de uma porta não alocada com atividade ser trocada por outra
	#define MAX_BLIND_PROCESSING 500 //número máximo de quadros que podem ser processados sem consultar a sugestão
	#define ALLOCATE_WHEN_INACTIVE_PROBABILITY 10//%
	
	//Para fins de testes
	#define USAGE_TIME 1 //tempo de utilização das threads
	#define TOGGLE_WAY 0 //quantidade de vezes que cada método de alternância de alocações foi empregado
#endif
