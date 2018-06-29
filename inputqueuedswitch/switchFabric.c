#include "switchFabric.h"

static inline void v2_rx_user_ready(struct tpacket2_hdr *hdr){
    hdr->tp_status = TP_STATUS_KERNEL;
    __sync_synchronize();
}
	
static inline int v2_rx_kernel_ready(struct tpacket2_hdr *hdr){
    return ((hdr->tp_status & TP_STATUS_USER) == TP_STATUS_USER);}

switchCtrlReg* createControlRegisters(){
	int i;
	
	switchCtrlReg* ctrl = (switchCtrlReg*) malloc(sizeof(switchCtrlReg));
	
	ctrl->mutex_forward_map = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t)*dataplane.port_count);
	ctrl->forwardingMap = (unsigned int**)malloc(sizeof(unsigned int*)*dataplane.port_count);
	
	//todos começam fora do poll
	ctrl->active = (bool*)calloc(dataplane.port_count,sizeof(bool));
	
	for(i=0;i<dataplane.port_count;i++){
		pthread_mutex_init((ctrl->mutex_forward_map)+i, NULL);
		//o mapa de encaminhamento começa vazio
		ctrl->forwardingMap[i] = (unsigned int*)calloc(dataplane.port_count,sizeof(unsigned int));
	}
	
	pthread_mutex_init(&(ctrl->mutex_total_sum), NULL);
	
	ctrl->totalSum=0;
	
	pthread_mutex_init(&(ctrl->mutex_alloc_port), NULL);	
	
	return ctrl;
}

//ESTA FUNÇÃO AINDA ESTÁ MUITO LENTA!! UNIR COM POLL QUANDO A BUSCA REALIZAR UMA VOLTA COMPLETA
//OU APENAS ENTRAR AQUI SE UM TIMEOUT FOR ESTOURADO (SEM MENSAGENS NA PORTA ATUAL)
//reserva uma porta de entrada ao datapath que fizer a chamada
static inline int allocPort(int partitionId, int currentPort,
	switchCtrlReg* ctrl, struct pollfd* localPfd, int* nlocalPfd){
	
	int firstPort, lastPort, portId;
	//encontra os limites dessa partição
	if(partitionId==0){
		firstPort = 0;
		lastPort = dataplane.partitions[0];
	}else{
		firstPort = dataplane.partitions[partitionId-1]+1;
		lastPort = dataplane.partitions[partitionId];
	}
	
	//encontra a próxima porta livre dentro da partição
	struct port* port_base = dataplane.ports;
	struct port* port;
	
	//antecessora da porta a partir da qual a busca se iniciará
	//(repare que na busca cíclica lastPort é a antecessora de 
	//firstPort)
	currentPort = (currentPort!=-1)?currentPort:lastPort;
	
	portId = currentPort;
	
	bool keepSearching = true;
	
	(*nlocalPfd) = 0;
	
	//inicia a sessão crítica
	pthread_mutex_lock(&(ctrl->mutex_alloc_port));
	
	do{
		portId++;
		portId = (portId>lastPort)?firstPort:portId;
		port = port_base + portId;
		
		//Se a porta estiver disponível e os frames estiverem prontos
		if(v2_rx_kernel_ready(port->rx_ring.rd[port->rx_ring.frame_num].iov_base)){
			if(port->free){
				port->free=false;//faça a reserva
				keepSearching = false;//finalize a busca
			}else if(portId==currentPort){
				//a busca deu uma volta completa sem sucesso
				portId = -1;
				keepSearching = false;//finalize a busca
			}
		}else{
			//monte o vetor de pfd para o poll	
			localPfd[(*nlocalPfd)].fd = dataplane.ports[portId].fd;
        	localPfd[(*nlocalPfd)].events = POLLIN | POLLERR;
        	localPfd[(*nlocalPfd)].revents = 0;
        	(*nlocalPfd)++;
        	//verifique a condição de parada
			if(portId==currentPort){
				//a busca deu uma volta completa sem sucesso
				portId = -1;
				keepSearching = false;//finalize a busca
				//monte o vetor de pfd para o poll
			}
		}
	}while(keepSearching);
	
	//finaliza a sessão crítica
	pthread_mutex_unlock(&(ctrl->mutex_alloc_port));
	
	return portId;
}

//avalia se é interessante ativar o send burst para determinada porta
static inline void tryToSend(switchCtrlReg* ctrl, int portNumber){
	int j;
	struct port* port = &dataplane.ports[portNumber];
	struct timespec now;
	
	clock_gettime(CLOCK_MONOTONIC,&now);
	
	//calcula quanto que o frame mais antigo do ring já esperou
	double dt = now.tv_sec - port->oldestFrameTime.t.tv_sec;
	dt += (now.tv_nsec - port->oldestFrameTime.t.tv_nsec)/1000000000.0;
	
	//Se tiver coisa para mandar
	if(port->oldestFrameTime.valid){
		//se tiver estourado o timeout (possível, porém não desejado)
		if(dt>SEND_TIMEOUT){
			sendBurst(port);
		}else{
			//caso desejável para a chamada send: quando não há frames destinados a essa porta.
			double p = 0;
			
			//calculando a probabilidade de uso desta porta no próximo intervalo de tempo
			for (j = 0; j < dataplane.port_count; j++) {
				if(ctrl->active[portNumber]){
					p+=ctrl->forwardingMap[j][portNumber];
				}
			}
			pthread_mutex_lock(&(ctrl->mutex_total_sum));
				p/=ctrl->totalSum;
			pthread_mutex_unlock(&(ctrl->mutex_total_sum));
			
			if(p < port->sendThreshold){
				sendBurst(port);
			}
		}
	}
}

void* commonDataPath(void* arg){
	int i,j;
	commonPathArg* Arg = (commonPathArg*) arg;
	int portNumber = -1;
	struct ring *rx_ring;
	union frame_map ppd;
	ubpf_jit_fn agent;
	struct metadatahdr* metadatahdr;
	uint64_t ret;
	int nLocalPfd;
	
	if(Arg->partitionId==0) nLocalPfd = dataplane.partitions[0]+1;
	else nLocalPfd = dataplane.partitions[Arg->partitionId]
		-dataplane.partitions[Arg->partitionId-1];
	
	struct pollfd* localPfd = (struct pollfd*) malloc(nLocalPfd*sizeof(struct pollfd));
	
	while (likely(!sigint)) {
		/*while(true){
			portNumber = allocPort(Arg->partitionId,portNumber,Arg->ctrl,localPfd,&nLocalPfd);
			if(portNumber==-1){//não há portas a serem processadas
				poll(localPfd, nLocalPfd, -1);//aguarde
			}else{
				break;//pare apenas quando tiver uma porta válida para processar
			}
		}*/
		portNumber = Arg->partitionId;
		rx_ring = &dataplane.ports[portNumber].rx_ring;
		while (v2_rx_kernel_ready(rx_ring->rd[rx_ring->frame_num].iov_base)) {
			//sinalizando que o datapath vai voltar à ativa
			Arg->ctrl->active[portNumber] = true;
			
			ppd.raw = rx_ring->rd[rx_ring->frame_num].iov_base;

			metadatahdr = (struct metadatahdr *)((uint8_t *)ppd.raw + TPACKET2_HDRLEN);
			metadatahdr->in_port = portNumber;
			metadatahdr->sec = ppd.v2->tp_h.tp_sec;
			metadatahdr->nsec = ppd.v2->tp_h.tp_nsec;
			metadatahdr->length = (uint16_t)ppd.v2->tp_h.tp_len;

			if (*(Arg->ubpf_fn) != NULL) {
				agent = *(Arg->ubpf_fn);
				ret = agent(metadatahdr, ppd.v2->tp_h.tp_len + sizeof(struct metadatahdr));
				transmit(metadatahdr, ppd.v2->tp_h.tp_len + sizeof(struct metadatahdr), (uint32_t)ret, 0);
			}

			v2_rx_user_ready(ppd.raw);//esse slot já pode ser preenchido com um novo quadro
			
			//move o ponteiro rx para o próximo slot
			rx_ring->frame_num = (rx_ring->frame_num + 1) % rx_ring->req.tp_frame_nr;
		
			int ovCell = -1;//se não for -1, consiste na coluna que está prestes a sofrer overflow
		
			//cria uma zona crítica associada aos valores que possivelmente serão modificados
			pthread_mutex_lock((Arg->ctrl->mutex_forward_map)+portNumber);
		
			if(ret==FLOOD){
				for (i = 0; i < dataplane.port_count; i++) {
					//a flag é acionada se pelo menos um registro estiver com seu valor igual ao máximo suportado pela
					//variável
					if(++Arg->ctrl->forwardingMap[portNumber][i]==MAXVAL_FORWARDINGMAP){
						ovCell=i;
					}
				}
			
				//atualizando o denominador da razão de probabilidade
				pthread_mutex_lock(&(Arg->ctrl->mutex_total_sum));
					Arg->ctrl->totalSum+=dataplane.port_count;
				pthread_mutex_unlock(&(Arg->ctrl->mutex_total_sum));
			
			}else if((ret!=CONTROLLER)&&(ret!=DROP)){
				//a flag é acionada se o registro estiver com seu valor igual ao máximo suportado pela
				//variável
				if(++Arg->ctrl->forwardingMap[portNumber][ret]==MAXVAL_FORWARDINGMAP){
					ovCell=ret;
				}
			
				//atualizando o denominador da razão de probabilidade
				pthread_mutex_lock(&(Arg->ctrl->mutex_total_sum));
					Arg->ctrl->totalSum++;
				pthread_mutex_unlock(&(Arg->ctrl->mutex_total_sum));
			}else{
				//atualizando o denominador da razão de probabilidade
				pthread_mutex_lock(&(Arg->ctrl->mutex_total_sum));
					Arg->ctrl->totalSum++;
				pthread_mutex_unlock(&(Arg->ctrl->mutex_total_sum));
			}
		
			pthread_mutex_unlock((Arg->ctrl->mutex_forward_map)+portNumber);
		
			if(ovCell>0){//se alguma posição está prestes a sofrer overflow
		
				//evita que qualquer outra thread acesse o mapa
				for(i=0;i<dataplane.port_count;i++){
					pthread_mutex_lock((Arg->ctrl->mutex_forward_map)+i);
				}
			
				//verifica novamente, desta vez em zona crítica
				if(Arg->ctrl->forwardingMap[portNumber][ovCell]==MAXVAL_FORWARDINGMAP){
			
					//divide todo o mapa por 2 (o que mantém a proporção entre as células
					for (i = 0; i < dataplane.port_count; i++) {
						for (j = 0; j < dataplane.port_count; j++) {
							Arg->ctrl->forwardingMap[i][j]=Arg->ctrl->forwardingMap[i][j]>>2;
						}
					}
			
					//atualizando o denominador da razão de probabilidade
					pthread_mutex_lock(&(Arg->ctrl->mutex_total_sum));
						Arg->ctrl->totalSum/=2;
					pthread_mutex_unlock(&(Arg->ctrl->mutex_total_sum));
			
				}
			
				for(i=0;i<dataplane.port_count;i++){
					pthread_mutex_unlock((Arg->ctrl->mutex_forward_map)+i);
				}
			}
		}
		//sinalizando que o datapath vai ficar inativo
		Arg->ctrl->active[portNumber] = false;
		//tenta enviar os frames dessa porta em rajada
		tryToSend(Arg->ctrl, portNumber);
		//libera a porta (fora de sessão crítica, visto que esta porta ficará naturalmente
		//indisponível para a alocação após ser desalocado aqui, ou seja, conflitos aqui não
		//causarão condições de corrida)
		dataplane.ports[portNumber].free=true;
	}
	free(localPfd);
	pthread_exit(NULL);
}

