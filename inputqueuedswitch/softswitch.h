#ifndef SOFT_SWITCH_H
#define SOFT_SWITCH_H
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
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

#include "ubpf.h"
#include "agent.h"
#include "ebpf_consts.h"

struct ring {
    struct iovec *rd;//sys/uio.h. Define um buffer eficiente (não sofre swap)
    uint8_t *map;//mapeamento (retorno da função mmap)
    struct tpacket_req req;//encapsula configurações do PACKET_MMAP
    int size;
    int frame_num;//número de frames (cada frame possui um pacote e um cabeçalho extra)
};

struct port {
    int fd;//identificador do socket
    struct ring rx_ring;//queue de entrada
    struct ring tx_ring;//queue de saída
};

struct dataplane {
    unsigned long long dpid;//identificador do plano de dados
    int port_count;//número de portas
    struct port *ports;//vetor com as portas
} dataplane;

extern sig_atomic_t sigint = 0;

union frame_map {//definição de um frame
    struct {
        struct tpacket2_hdr tp_h __aligned_tpacket;
        struct sockaddr_ll s_ll __align_tpacket(sizeof(struct tpacket2_hdr));
    } *v2;
    void *raw;
};

void sighandler(int num);

//configura o ring e o mapeamento PACKET_MMAP
int setup_ring(int fd, struct ring* ring, int ring_type);


//abre e configura um socket para cada par de portas de entrada/saída
int setup_socket(struct port *port, char *netdev);


//liberação do mapeamento e das estruturas
void teardown_socket(struct port *port);

inline int v2_rx_kernel_ready(struct tpacket2_hdr *hdr){
    return ((hdr->tp_status & TP_STATUS_USER) == TP_STATUS_USER);}
inline void v2_rx_user_ready(struct tpacket2_hdr *hdr){
    hdr->tp_status = TP_STATUS_KERNEL;
    __sync_synchronize();}
inline int v2_tx_kernel_ready(struct tpacket2_hdr *hdr){
    return !(hdr->tp_status & (TP_STATUS_SEND_REQUEST | TP_STATUS_SENDING));}
inline void v2_tx_user_ready(struct tpacket2_hdr *hdr){
    hdr->tp_status = TP_STATUS_SEND_REQUEST;
    __sync_synchronize();}

//envia um frame pela porta de saída correta
int tx_frame(struct port* port, void *data, int len);

//gera um id aleatório para o plano de dados
unsigned long long random_dpid();
//executa uma ação sobre um pacote
// flags is the hack to force transmission
void transmit(struct metadatahdr *buf, int len, uint32_t port, int flags);
#endif

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