#ifndef SWITCH_FABRIC

	#define SWITCH_FABRIC
	#include <pthread.h>
	#include <sched.h>
	#include <stdio.h>
	#include <stdlib.h>
	#include <stdbool.h>
	#include <time.h>
	#include "config.h"
	#include "softswitch.h"
	
	//estrutura utilizada para sincronizar as threads
	typedef struct{
			pthread_mutex_t* mutex_forward_map;//protege cada linha do mapa
			unsigned int** forwardingMap;//estrutura para estimar quanto do fluxo que passa por cada
			//porta de entrada (linha) vai para cada porta de saída (coluna)
			pthread_mutex_t mutex_total_sum;//proteje a variável abaixo
			long long int totalSum;//soma total dos valores da estrutura (denominador da razão
			//de probabilidade)
			bool* active;//vetor de flags sinalizadas pelo próprio caminho de dados indicando que a
			//porta correspondente está ativa
			pthread_mutex_t mutex_alloc_port;//para apenas um alocar por vez
			
			int* suggestedPort;//indica qual deve ser a próxima porta para cada caminho de dados
	}switchCtrlReg;

	switchCtrlReg* createControlRegisters(int nDatapaths);
	
	//argumentos necessários para a operação dos caminhos de dados
	//dedicados a cada porta de entrada
	typedef struct{
        	switchCtrlReg* ctrl;//dá acesso ao registro de controle
	        int datapathId;//identificador do caminho de dados
			ubpf_jit_fn* ubpf_fn;//ponteiro do ponteiro da função do agente eBPF
	}commonPathArg;

	void* commonDataPath(void* arg);

#endif
