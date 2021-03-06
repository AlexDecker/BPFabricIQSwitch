#include "softswitch.h"

//configura o ring e o mapeamento PACKET_MMAP
int setup_ring(int fd, struct ring* ring, int ring_type)
{
    int err;
    unsigned int blocknum = 256;

    memset(&ring->req, 0, sizeof(ring->req));

    //configurações do mapeamento PACKET_MMAP
    ring->req.tp_block_size = getpagesize() << 2;
    ring->req.tp_frame_size = TPACKET_ALIGNMENT << 7;
    ring->req.tp_block_nr = blocknum;
    ring->req.tp_frame_nr = ring->req.tp_block_size /
                            ring->req.tp_frame_size *
                            ring->req.tp_block_nr;
    
    //determinação do tamanho do ring
    ring->size = ring->req.tp_block_size * ring->req.tp_block_nr;

    //instalando as configurações (em ring->req. ring_type define rx/tx)
    err = setsockopt(fd, SOL_PACKET, ring_type, &ring->req, sizeof(ring->req));
    if (err < 0) {
        perror("setsockopt");
        exit(1);
    }

    return 0;
}


//abre e configura um socket para cada par de portas de entrada/saída
int setup_socket(struct port *port, char *netdev)
{
    int err, i, fd, ifindex, v = TPACKET_V2;
    struct sockaddr_ll ll;

    ifindex = if_nametoindex(netdev);
    if (ifindex == 0) {
        perror("interface");
        exit(1);
    }

    //abrindo o socket L2
    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        perror("socket");
        exit(1);
    }
	
    port->fd = fd;
	pthread_mutex_init(&(port->mutex_tx_frame), NULL);
	port->framesWaiting = 0;
	port->oldestFrameTime.valid=false;
	
	clock_gettime(CLOCK_MONOTONIC,&(port->oldestFrameTime.t));
	
	port->droppedFrames = -1;
	port->droppedFrames_old = -1;
	port->sendThreshold = SEND_THRESHOLD_0;
	port->sendThreshold_old = SEND_THRESHOLD_0;
	
	port->datapathId = -1;
	pthread_mutex_init(&(port->mutex_allocate), NULL);

    err = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
    if (err < 0) {
        perror("setsockopt");
        exit(1);
    }

    // NOTE: disable qdisc, trivial performance improvement
    // int one = 1;
    // setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &one, sizeof(one));

    setup_ring(fd, &port->rx_ring, PACKET_RX_RING);
    setup_ring(fd, &port->tx_ring, PACKET_TX_RING);

    //mapeia o socket aos rings
    port->rx_ring.map = mmap(NULL, port->rx_ring.size + port->tx_ring.size,
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);

    if (port->rx_ring.map == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    port->tx_ring.map = port->rx_ring.map + port->rx_ring.size;

    // rd_num * sizeof(*ring->rd)
    int rx_len_iovec = port->rx_ring.req.tp_frame_nr * sizeof(*port->rx_ring.rd);
    int tx_len_iovec = port->tx_ring.req.tp_frame_nr * sizeof(*port->tx_ring.rd);

    port->rx_ring.rd = malloc(rx_len_iovec); // allocate iovec for each block
    port->tx_ring.rd = malloc(tx_len_iovec);

    // why not use calloc?
    memset(port->rx_ring.rd, 0, rx_len_iovec);
    memset(port->tx_ring.rd, 0, tx_len_iovec);

    // TODO check if ring->rd is allocated properly
    // printf("number of frames: %d\n", port->rx_ring.req.tp_frame_nr);
    for (i = 0; i < port->rx_ring.req.tp_frame_nr; ++i) {
        port->rx_ring.rd[i].iov_base = port->rx_ring.map + (i * port->rx_ring.req.tp_frame_size);
        port->rx_ring.rd[i].iov_len = port->rx_ring.req.tp_frame_size;
    }

    for (i = 0; i < port->tx_ring.req.tp_frame_nr; ++i) {
        port->tx_ring.rd[i].iov_base = port->tx_ring.map + (i * port->tx_ring.req.tp_frame_size);
        port->tx_ring.rd[i].iov_len = port->tx_ring.req.tp_frame_size;
    }

    //bind do socket
    memset(&ll, 0, sizeof(ll));
    ll.sll_family = PF_PACKET;
    ll.sll_protocol = htons(ETH_P_ALL);
    ll.sll_ifindex = ifindex;
    ll.sll_hatype = 0;
    ll.sll_pkttype = 0;
    ll.sll_halen = 0;

    err = bind(fd, (struct sockaddr *) &ll, sizeof(ll));
    if (err < 0) {
        perror("bind");
        exit(1);
    }

    return fd;
}


//liberação do mapeamento e das estruturas
void teardown_socket(struct port *port){
    munmap(port->tx_ring.map, port->tx_ring.size);
    munmap(port->rx_ring.map, port->rx_ring.size);

    free(port->tx_ring.rd);
    free(port->rx_ring.rd);
    
	pthread_mutex_destroy(&(port->mutex_tx_frame));
	pthread_mutex_destroy(&(port->mutex_allocate));
	
    close(port->fd);
}

//envia um frame pela porta de saída correta
int tx_frame(struct port* port, void *data, int len) {
	int ret = 0;
    // add the packet to the port tx queue
    struct ring *tx_ring = &port->tx_ring;

    pthread_mutex_lock(&(port->mutex_tx_frame));
    
	struct tpacket2_hdr *hdr = tx_ring->rd[tx_ring->frame_num].iov_base;
	
	if (hdr->tp_status & TP_STATUS_SEND_REQUEST) {
		//o ring encheu, envie (caso possível, porém não desejado)
		sendBurst(port);
	}else if (hdr->tp_status & TP_STATUS_SENDING){
		//descarte o quadro
	}else{
	
	    union frame_map ppd_out;
	    ppd_out.raw = hdr;
	    
	    ppd_out.v2->tp_h.tp_snaplen = len;
	    ppd_out.v2->tp_h.tp_len = len;

	    memcpy((uint8_t *) ppd_out.raw + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll),
	        (uint8_t *) data,
	        len);

	    ppd_out.v2->tp_h.tp_status = TP_STATUS_SEND_REQUEST;

	    //
	    tx_ring->frame_num = (tx_ring->frame_num + 1) % tx_ring->req.tp_frame_nr;

	    ret = 1; //kernel pronto, não descarte o pacote
	    port->framesWaiting++;
	    
	    if(port->framesWaiting == port->tx_ring.req.tp_frame_nr/SIZE_DIVIDER){
	    	//se começar a encher a fila, envie (possível, porém não desejado)
	    	sendBurst(port);
	    }else if(!port->oldestFrameTime.valid){
	    	//o frame que acabou de ser enviado é agora o mais antigo em TP_STATUS_SEND_REQUEST
	    	clock_gettime(CLOCK_MONOTONIC,&(port->oldestFrameTime.t));
	    	port->oldestFrameTime.valid = true;
	    }
	}
    
    pthread_mutex_unlock(&(port->mutex_tx_frame));
    return ret;
}

void sendBurst(struct port* port){
	send(port->fd, NULL, 0, MSG_DONTWAIT);
	
	double newThreshold = 0.5;
	
	port->framesWaiting = 0;
	port->oldestFrameTime.valid=false;
	
	port->droppedFrames_old = port->droppedFrames;
	port->droppedFrames = 0;
	port->sendThreshold_old = port->sendThreshold;
	port->sendThreshold = newThreshold;
}

//gera um id aleatório para o plano de dados
unsigned long long random_dpid() {
    srand(time(NULL));
    unsigned long long dpid = 0;
    dpid = rand() & 0xFFFFFFFF;//gera um número aleatório de 32 bits
    return dpid;
}

//executa uma ação sobre um pacote
// flags is the hack to force transmission
int transmit(struct metadatahdr *buf, int len, uint32_t port, int flags) {
	int ret=0;
    int i;
    void *eth_frame = (uint8_t *)buf + sizeof(struct metadatahdr);
    int eth_len = len - sizeof(struct metadatahdr);

    switch (port) {
        case FLOOD:
            // printf("Flooding the packet\n");
            for (i = 0; i < dataplane.port_count; i++) {
                if (i != buf->in_port) {
                    // printf("sending frame from port %d to port %d on switch %llu\n", buf->in_port, i, dataplane.dpid);
                    ret+=tx_frame(&dataplane.ports[i], eth_frame, eth_len);
                }
            }
			
			//TODO: TIRAR ESSE TREM DAQUI
            // HACK, the packets are only sent after poll() however this
            // can be called asynchronously on packet from the controller and
            // therefore delay the packet transmission until the next packet is received
            if (flags) {
                for (i = 0; i < dataplane.port_count; i++) {
                    sendBurst(dataplane.ports+i);
                }
            }

            break;
        //
        case CONTROLLER:
            // printf("Sending to controller\n");
            agent_packetin(buf, len, buf->in_port);//o último campo é o identificador do agente (correspondente à porta)
            break;
        //
        case DROP:
            // printf("Dropping the packet\n");
            break;

        default:
            // printf("Forwarding the packet\n");
            // printf("in_port %d out_port %lu data_len %lu\n", buf->in_port, port, len - sizeof(struct metadatahdr));
            ret+=tx_frame(&dataplane.ports[port], eth_frame, eth_len);
    }
    return ret;
}
