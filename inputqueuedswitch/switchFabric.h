#ifndef SWITCH_FABRIC

	#define SWITCH_FABRIC
	#include <pthread.h>
	#include <sched.h>
	#include <stdio.h>
	#include <stdlib.h>
	#include <stdbool.h>
	#include "softswitch.h"

	//estrutura utilizada para sincronizar as threads
	typedef struct{
        	bool running;//se false, as threads devem finalizar
			pthread_mutex_t mutex;
			int nReady;//número de threads que aguardam um poll
	}switchCtrlReg;

	switchCtrlReg* createControlRegisters();

	//argumentos necessários para a operação do caminho de dados
	//principal (que atua sobre todo o fabric)
	typedef struct{
        	switchCtrlReg* ctrl;
			int nPorts;
			commonPathArg* allCommonPaths;
			struct pollfd* pfds;
	}mainPathArg;

	//argumentos necessários para a operação dos caminhos de dados
	//dedicados a cada porta de entrada
	typedef struct{
        	switchCtrlReg* ctrl;//dá acesso ao registro de controle
			bool imReady;//a thread comum autoriza a principal a dar poll
	        int id;//útil para prints em depurações
			struct port* port;
	}commonPathArg;

	void* mainBPFabricPath(void* arg);

	void* commonDataPath(void* arg);

#endif
