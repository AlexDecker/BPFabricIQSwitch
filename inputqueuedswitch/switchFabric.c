#include "switchFabric.h"

static inline void v2_rx_user_ready(struct tpacket2_hdr *hdr){
    hdr->tp_status = TP_STATUS_KERNEL;
    __sync_synchronize();
}
	
static inline int v2_rx_kernel_ready(struct tpacket2_hdr *hdr){
	return (hdr->tp_status & TP_STATUS_USER);
}

switchCtrlReg* createControlRegisters(int nDatapaths){
	int i;
	
	switchCtrlReg* ctrl = (switchCtrlReg*) malloc(sizeof(switchCtrlReg));
	
	ctrl->mutex_forward_map = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t)*dataplane.port_count);
	ctrl->forwardingMap = (unsigned int**)malloc(sizeof(unsigned int*)*dataplane.port_count);
	
	ctrl->active = (bool*)calloc(dataplane.port_count,sizeof(bool));
	
	for(i=0;i<dataplane.port_count;i++){
		pthread_mutex_init((ctrl->mutex_forward_map)+i, NULL);
		//o mapa de encaminhamento começa vazio
		ctrl->forwardingMap[i] = (unsigned int*)calloc(dataplane.port_count,sizeof(unsigned int));
	}
	
	pthread_mutex_init(&(ctrl->mutex_total_sum), NULL);
	
	ctrl->totalSum=0;
	
	ctrl->suggestedPort = (int*) malloc(sizeof(int)*nDatapaths);
	for(i=0; i<nDatapaths; i++){
		ctrl->suggestedPort[i] = -1;
	}
	ctrl->nDatapaths = nDatapaths;
	
	#if TOGGLE_WAY
		ctrl->count1=0;
		ctrl->count2=0;
	#endif
	
	return ctrl;
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
	int i,j, processedFrames;
	int portNumber = -1;
	int count = 0;
	int ovCell;
	uint64_t ret;
	
	commonPathArg* Arg = (commonPathArg*) arg;
	
	struct port* port;
	struct ring *rx_ring;
	union frame_map ppd;
	ubpf_jit_fn eBPFEngine;
	struct metadatahdr* metadatahdr;
	
	printf("Starting datapath %d\n",Arg->datapathId);
	
	while (likely(!sigint)) {
		//tente ler enquanto o número não for válido
		do{
			portNumber = Arg->ctrl->suggestedPort[Arg->datapathId];
		}while((portNumber<0)||(portNumber>dataplane.port_count));
		
		port = dataplane.ports+portNumber;
		pthread_mutex_lock(&(port->mutex_allocate));
		rx_ring = &(port->rx_ring);
		processedFrames = 0;
		
		while (v2_rx_kernel_ready(rx_ring->rd[rx_ring->frame_num].iov_base)) {
			//PARA GERAÇÃO DE RESULTADOS
			#if USAGE_TIME
				struct timespec antes,depois;
				clock_gettime(CLOCK_MONOTONIC,&antes);
			#endif
			/////////////////////////
			//verificando se a porta não foi realocada para alguém
			//ou se já não estar na hora de chegar suggestedPort novamente
			if(((port->datapathId!=-1)&&(port->datapathId!=Arg->datapathId))
				||(processedFrames>MAX_BLIND_PROCESSING)){
				break;
			}
			//sinalizando que o datapath vai voltar à ativa
			Arg->ctrl->active[portNumber] = true;
			
			ppd.raw = rx_ring->rd[rx_ring->frame_num].iov_base;

			metadatahdr = (struct metadatahdr *)((uint8_t *)ppd.raw + TPACKET2_HDRLEN);
			metadatahdr->in_port = portNumber;
			metadatahdr->sec = ppd.v2->tp_h.tp_sec;
			metadatahdr->nsec = ppd.v2->tp_h.tp_nsec;
			metadatahdr->length = (uint16_t)ppd.v2->tp_h.tp_len;

			if (*(Arg->ubpf_fn[port->partitionId]) != NULL) {
				eBPFEngine = *(Arg->ubpf_fn[port->partitionId]);
				ret = eBPFEngine(metadatahdr, ppd.v2->tp_h.tp_len + sizeof(struct metadatahdr));
				transmit(metadatahdr, ppd.v2->tp_h.tp_len + sizeof(struct metadatahdr), (uint32_t)ret, 0);
			}else{
				#if USAGE_TIME
				clock_gettime(CLOCK_MONOTONIC,&(Arg->ctrl->antes));
				#endif
			}
			
			v2_rx_user_ready(ppd.raw);//esse slot já pode ser preenchido com um novo quadro
			
			//move o ponteiro rx para o próximo slot
			rx_ring->frame_num = (rx_ring->frame_num + 1) % rx_ring->req.tp_frame_nr;
			
			if(count==UPDATE_STATS){
				count = 0;
				ovCell = -1;//se não for -1, consiste na coluna que está prestes a sofrer overflow
		
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
			}else{
				count++;
			}
			processedFrames++;
			//PARA GERAÇÃO DE RESULTADOS
			#if USAGE_TIME
				clock_gettime(CLOCK_MONOTONIC,&depois);
				double dt = depois.tv_sec - antes.tv_sec;
				dt += (depois.tv_nsec - antes.tv_nsec)/1000000000.0;
				*(Arg->tempo) += dt;
			#endif
			////////////////////
		}
		//sinalizando que o datapath vai ficar inativo
		Arg->ctrl->active[portNumber] = false;
		//tenta enviar os frames dessa porta em rajada
		tryToSend(Arg->ctrl, portNumber);
		pthread_mutex_unlock(&(port->mutex_allocate));
	}
	pthread_exit(NULL);
}

//aloca dinamicamente caminhos de dados para processar as portas de entrada
//considera que todos os caminhos de dados começam alocados
void crossbarAnycast(switchCtrlReg* ctrl){
	
	int i, rnd, datapathId;
	int nPorts = dataplane.port_count;
	
	//ring buffer para armazenar portas eventualmente sem atividade
	int idlePorts[nPorts];
	bool inIdlePorts[nPorts];
	for(i=0;i<nPorts;i++){
		idlePorts[i]=-1;//trocar por memset
		inIdlePorts[i] = false;
	}
	int removeIndex = 0;
	int insertIndex = 0;
	
	struct port* ports = dataplane.ports;
	struct port* port;
	struct ring *rx_ring;
	
	int i_aux;
	struct port* port_aux;
	
	for(i=0;i<nPorts;i++){
		port = ports+i;
		rx_ring = &(port->rx_ring);
		if(port->datapathId==-1){//se não está alocada
			if(!ctrl->active[i]){//se de fato ninguém está trabalhando nela
				rnd = rand()%100;
				if((v2_rx_kernel_ready(rx_ring->rd[rx_ring->frame_num].iov_base))
					||(rnd < ALLOCATE_WHEN_INACTIVE_PROBABILITY)) {				
					//busque portas alocadas mas sem atividade
					while(true){
						if(insertIndex==removeIndex){//idlePorts está vazio
							//Decida se vai desalocar uma porta com atividade
							//ou manterá como está
							rnd = rand()%100;
							if(rnd < TOGGLE_PROBABILITY){
								datapathId = rand()%(ctrl->nDatapaths);//encontre um datapath qualquer
								i_aux = ctrl->suggestedPort[datapathId];
								if(i_aux!=-1){//se já estava alocado, desaloque
									port_aux = ports + i_aux;
									port_aux->datapathId = -1;
								}
								#if TOGGLE_WAY
									ctrl->count2++;
								#endif
								//aloque a porta i para esse datapath
								port->datapathId = port_aux->datapathId;
								ctrl->suggestedPort[datapathId] = i;
							}
							break;
						}
						//remova o próximo item da lista
						i_aux = idlePorts[removeIndex];
						idlePorts[removeIndex] = -1;
						removeIndex = (removeIndex+1)%nPorts;
						inIdlePorts[i_aux] = false;
				
						//verifique se ainda está sem atividade
						port_aux = ports + i_aux;
						if(!ctrl->active[i_aux]){
							//se estiver, passe o caminho de dados dessa para a que está sem
							#if TOGGLE_WAY
								ctrl->count1++;
							#endif
							port->datapathId = port_aux->datapathId;
							port_aux->datapathId = -1;
							ctrl->suggestedPort[port->datapathId] = i;
						}
					}			
				}
			}
		}else if(!ctrl->active[i]){
			//se a porta estiver alocada, porém sem atividade
			if((idlePorts[insertIndex]==-1)&&(!inIdlePorts[i])){
				//se estiver vazio e a porta já não estiver inserida
				idlePorts[insertIndex] = i;
				insertIndex = (insertIndex+1)%nPorts;
				inIdlePorts[i] = true;
			}
		}
			
	}
}
