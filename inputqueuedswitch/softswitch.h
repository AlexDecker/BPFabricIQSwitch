#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include <time.h>

#include <pthread.h>

#include "ubpf.h"
#include "multiAgent.h"
#include "ebpf_consts.h"
#include "config.h"

#ifndef likely
    #define likely(x)        __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
    #define unlikely(x)        __builtin_expect(!!(x), 0)
#endif

#ifndef __aligned_tpacket
    #define __aligned_tpacket    __attribute__((aligned(TPACKET_ALIGNMENT)))
#endif
#ifndef __align_tpacket
    #define __align_tpacket(x)    __attribute__((aligned(TPACKET_ALIGN(x))))
#endif

#ifndef SOFT_SWITCH_H
	#define SOFT_SWITCH_H
	
	extern sig_atomic_t sigint;//declaração

	//estrutura utilizada para o timeout das chamadas de send
	typedef struct{
			struct timespec t;//marca o tempo em que o frame mais antigo que ainda está no
			//ring chegou
			bool valid;//indica se o valor deve ser atualizado quando o próximo frame chegar
	}timeCounter;

	struct ring {
		struct iovec *rd;//sys/uio.h. Define um buffer eficiente (não sofre swap)
		uint8_t *map;//mapeamento (retorno da função mmap)
		struct tpacket_req req;//encapsula configurações do PACKET_MMAP
		int size;
		int frame_num;//número de frames (cada frame possui um pacote e um cabeçalho extra)
	};

	struct port {
		int fd;//identificador do socket
		pthread_mutex_t mutex_tx_frame;//evita conflitos de transmissão na porta de saída
		//
		struct ring rx_ring;//queue de entrada
		struct ring tx_ring;//queue de saída
		//
		int framesWaiting;//número de quadros esperando por send
		timeCounter oldestFrameTime;//marca o tempo em que o frame mais antigo que ainda está no
		//tx_ring chegou
		//
		long long int droppedFrames;//número de quadros descartados desde a última chamada a send
		long long int droppedFrames_old;//último valor de droppedFrames
		double sendThreshold;//threshold utilizado para decidir se uma chamada a send() é apropriada
		//no presente momento
		double sendThreshold_old;//último valor de sendThreshold
		//
		int partitionId;
		//
		int datapathId;//datapath que alocou essa porta
		pthread_mutex_t mutex_allocate;//evita que dois caminhos de dados processem a mesma porta
		//ao mesmo tempo
	};

	struct dataplane {
		unsigned long long dpid;//identificador do plano de dados
		int port_count;//número de portas
		struct port *ports;//vetor com as portas
	} dataplane;

	union frame_map {//definição de um frame
		struct {
		    struct tpacket2_hdr tp_h __aligned_tpacket;
		    struct sockaddr_ll s_ll __align_tpacket(sizeof(struct tpacket2_hdr));
		} *v2;
		void *raw;
	};

	//configura o ring e o mapeamento PACKET_MMAP
	int setup_ring(int fd, struct ring* ring, int ring_type);


	//abre e configura um socket para cada par de portas de entrada/saída
	int setup_socket(struct port *port, char *netdev);


	//liberação do mapeamento e das estruturas
	void teardown_socket(struct port *port);

	//envia um frame pela porta de saída correta
	int tx_frame(struct port* port, void *data, int len);

	//envia todos os frames marcados com REQUEST TO SEND de uma port
	void sendBurst(struct port* port);

	//gera um id aleatório para o plano de dados
	unsigned long long random_dpid();

	//executa uma ação sobre um pacote
	// (flags is the hack to force transmission)
	//retorna quantos quadros foram transmitidos
	int transmit(struct metadatahdr *buf, int len, uint32_t port, int flags);
#endif
