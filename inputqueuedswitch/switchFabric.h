#ifndef SWITCH_FABRIC

	#define SWITCH_FABRIC
        #include <pthread.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <stdbool.h>

	//estrutura utilizada para sincronizar as threads
	typedef struct{
        	bool running;
	}switchCtrlReg;

	switchCtrlReg* createControlRegisters();

	//argumentos necessários para a operação do caminho de dados
	//principal (que atua sobre todo o fabric)
	typedef struct{
        	switchCtrlReg* ctrl;
	}mainPathArg;

	//argumentos necessários para a operação dos caminhos de dados
	//dedicados a cada porta de entrada
	typedef struct{
        	switchCtrlReg* ctrl;
	        int id;
	}commonPathArg;

	void* mainBPFabricPath(void* arg);

	void* commonDataPath(void* arg);

#endif
