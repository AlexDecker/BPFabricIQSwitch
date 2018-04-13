#include "switchFabric.h"

switchCtrlReg* createControlRegisters(){
        switchCtrlReg* ctrl = (switchCtrlReg*) malloc(sizeof(switchCtrlReg));
        ctrl->running = true;
        return ctrl;
}

void* mainBPFabricPath(void* arg){
        mainPathArg* Arg = (mainPathArg*) arg;
        int n=0;
        while(Arg->ctrl->running){
                //realiza o metadata prepend inserindo um ponteiro pra estrutura de filas
                //executa o programa eBFP
                //recupera o resultado da execução (grafo bipartido sem conflitos)
                //retira da fila de saída os pacotes a serem enviados
                //envia os pacotes
                printf("Caminho principal\n");
                n++;
                if(n==10000) Arg->ctrl->running = false;
        }
}

void* commonDataPath(void* arg){
        commonPathArg* Arg = (commonPathArg*) arg;
        int n=0;
        while(Arg->ctrl->running){
                //retira um novo pacote da fila de entrada
                //realiza o metadata prepend
                //executa o programa eBPF
                //adiciona a ação desejada aos metadados
                //insere o pacote na fila de saída
                n++;
                printf("Caminho da fila da porta %d, iteracao %d\n", Arg->id,n);
        }
}

