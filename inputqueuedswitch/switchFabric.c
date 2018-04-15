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
	return ctrl;
}

void* mainBPFabricPath(void* arg){
	int i;
	mainPathArg* Arg = (mainPathArg*) arg;
	while (likely(!sigint)) {
		//realiza o metadata prepend inserindo um ponteiro pra estrutura de filas
		//executa o programa eBFP
		//recupera o resultado da execução (grafo bipartido sem conflitos)
		//retira da fila de saída os pacotes a serem enviados
		//envia os pacotes
		if(Arg->ctrl->nReady==Arg->nPorts){//se todas já estão prontas
			pthread_mutex_lock(&(Arg->ctrl->mutex));
			// Send all the pendings packets for each interface
			for (i = 0; i < Arg->nPorts; i++) {
				struct port* porta = Arg->allCommonPaths[i].port;
				send(porta->fd, NULL, 0, MSG_DONTWAIT);
				Arg->allCommonPaths[i].imReady = false;
			}

			// Poll for the next socket POLLIN or POLLERR
			poll(Arg->pfds, Arg->nPorts, -1);
			pthread_mutex_unlock(&(Arg->ctrl->mutex));
		}else{//nada a fazer, apenas durma
			sched_yield();
		}
	}
	Arg->ctrl->running = false;//finaliza as outras threads
}

void* commonDataPath(void* arg){
	commonPathArg* Arg = (commonPathArg*) arg;
	
	while(Arg->ctrl->running){
		//retira um novo pacote da fila de entrada
		//realiza o metadata prepend
		//executa o programa eBPF
		//adiciona a ação desejada aos metadados
		//insere o pacote na fila de saída
		if(!Arg->imReady){//se ainda não tiver terminado de processar
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
					transmit(metadatahdr, ppd.v2->tp_h.tp_len + sizeof(struct metadatahdr), (uint32_t)ret, 0);
				}

				// Frame has been used, release the buffer space
				v2_rx_user_ready(ppd.raw);
				rx_ring->frame_num = (rx_ring->frame_num + 1) % rx_ring->req.tp_frame_nr;
			}else{
				Arg->imReady = true;
				Arg->ctrl->nReady++;
			}
		}else{//nada a fazer, apenas durma
			sched_yield();
		}
	}
}

