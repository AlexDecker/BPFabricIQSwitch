#include "switchFabric.h"

static inline void v2_rx_user_ready(struct tpacket2_hdr *hdr){
    hdr->tp_status = TP_STATUS_KERNEL;
    __sync_synchronize();}
	
static inline int v2_rx_kernel_ready(struct tpacket2_hdr *hdr){
    return ((hdr->tp_status & TP_STATUS_USER) == TP_STATUS_USER);}

switchCtrlReg* createControlRegisters(){
	switchCtrlReg* ctrl = (switchCtrlReg*) malloc(sizeof(switchCtrlReg));
	ctrl->running = true;
	pthread_mutex_init(&(ctrl->mutex), NULL);
	ctrl->nReady = 0;
	ctrl->preparingfase=false;
	return ctrl;
}

void* mainBPFabricPath(void* arg){
	int i;
	mainPathArg* Arg = (mainPathArg*) arg;
	printf("Initializing main datapath\n");
	while (likely(!sigint)) {
		//realiza o metadata prepend inserindo um ponteiro pra estrutura de filas
		//executa o programa eBFP
		//recupera o resultado da execução (grafo bipartido sem conflitos)
		//retira da fila de saída os pacotes a serem enviados
		//envia os pacotes
		if(Arg->ctrl->nReady==Arg->nPorts){//se todas já estão prontas
			printf("All ports ready\n");
			Arg->ctrl->preparingfase = true;
			// Send all the pendings packets for each interface
			for (i = 0; i < Arg->nPorts; i++) {
				struct port* porta = Arg->allCommonPaths[i].port;
				send(porta->fd, NULL, 0, MSG_DONTWAIT);
				Arg->allCommonPaths[i].imReady = false;
			}

			// Poll for the next socket POLLIN or POLLERR
			poll(Arg->pfds, Arg->nPorts, -1);
			Arg->ctrl->preparingfase = false;
		}else{//nada a fazer, apenas durma
			//printf("Main datapath must rest\n");
			//sched_yield();
		}
	}
	Arg->ctrl->running = false;//finaliza as outras threads
}

void* commonDataPath(void* arg){
	commonPathArg* Arg = (commonPathArg*) arg;
	
	printf("Initializing datapath for port %d\n",Arg->portNumber);
	
	while(Arg->ctrl->running){
		//retira um novo pacote da fila de entrada
		//realiza o metadata prepend
		//executa o programa eBPF
		//adiciona a ação desejada aos metadados
		//insere o pacote na fila de saída
		if((!Arg->imReady)&&(!Arg->ctrl->preparingfase)){//se ainda não tiver terminado de processar
			struct ring* rx_ring = &(Arg->port->rx_ring);
			if (v2_rx_kernel_ready(rx_ring->rd[rx_ring->frame_num].iov_base)){
				union frame_map ppd;
				ppd.raw = rx_ring->rd[rx_ring->frame_num].iov_base;

				struct metadatahdr *metadatahdr = (struct metadatahdr *)((uint8_t *)ppd.raw + TPACKET2_HDRLEN);
				metadatahdr->in_port = Arg->portNumber;
				metadatahdr->sec = ppd.v2->tp_h.tp_sec;
				metadatahdr->nsec = ppd.v2->tp_h.tp_nsec;
				metadatahdr->length = (uint16_t)ppd.v2->tp_h.tp_len;

				/* Here we have the packet and we can do whatever we want with it */
				if (Arg->ubpf_fn != NULL) {
					uint64_t ret = Arg->ubpf_fn(metadatahdr, ppd.v2->tp_h.tp_len + sizeof(struct metadatahdr));
					printf("Datapath of port %d started executing an action\n",Arg->portNumber);
					pthread_mutex_lock(&(Arg->ctrl->mutex));
					transmit(metadatahdr, ppd.v2->tp_h.tp_len + sizeof(struct metadatahdr), (uint32_t)ret, 0);
					pthread_mutex_unlock(&(Arg->ctrl->mutex));
					printf("Datapath of port %d finished executing an action\n",Arg->portNumber);
				}else{
					printf("Datapath of port %d got a null agent!\n",Arg->portNumber);
				}

				// Frame has been used, release the buffer space
				v2_rx_user_ready(ppd.raw);
				rx_ring->frame_num = (rx_ring->frame_num + 1) % rx_ring->req.tp_frame_nr;
			}else{
				printf("Datapath of port %d finished the entire queue\n",Arg->portNumber);
				Arg->imReady = true;
				Arg->ctrl->nReady++;
			}
		}else{//nada a fazer, apenas durma
			printf("Datapath of port %d must rest\n",Arg->portNumber);
			//sched_yield();
		}
	}
}

