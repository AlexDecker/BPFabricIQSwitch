#include "switchFabric.h"

static inline void v2_rx_user_ready(struct tpacket2_hdr *hdr){
    hdr->tp_status = TP_STATUS_KERNEL;
    __sync_synchronize();}
	
static inline int v2_rx_kernel_ready(struct tpacket2_hdr *hdr){
    return ((hdr->tp_status & TP_STATUS_USER) == TP_STATUS_USER);}

switchCtrlReg* createControlRegisters(){
	switchCtrlReg* ctrl = (switchCtrlReg*) malloc(sizeof(switchCtrlReg));
	pthread_mutex_init(&(ctrl->mutex_nReady), NULL);
	ctrl->nReady = 0;
	ctrl->preparingfase=false;
	return ctrl;
}

void* commonDataPath(void* arg){
	commonPathArg* Arg = (commonPathArg*) arg;
	struct ring *rx_ring = &dataplane.ports[Arg->portNumber].rx_ring;
	union frame_map ppd;
	ubpf_jit_fn agent;
	struct metadatahdr* metadatahdr;
	uint64_t ret;
	
	while (likely(!sigint)) {
			while (v2_rx_kernel_ready(rx_ring->rd[rx_ring->frame_num].iov_base)) {
				ppd.raw = rx_ring->rd[rx_ring->frame_num].iov_base;

				metadatahdr = (struct metadatahdr *)((uint8_t *)ppd.raw + TPACKET2_HDRLEN);
				metadatahdr->in_port = Arg->portNumber;
				metadatahdr->sec = ppd.v2->tp_h.tp_sec;
				metadatahdr->nsec = ppd.v2->tp_h.tp_nsec;
				metadatahdr->length = (uint16_t)ppd.v2->tp_h.tp_len;

				if (*(Arg->ubpf_fn) != NULL) {
					agent = *(Arg->ubpf_fn);
					ret = agent(metadatahdr, ppd.v2->tp_h.tp_len + sizeof(struct metadatahdr));
					transmit(metadatahdr, ppd.v2->tp_h.tp_len + sizeof(struct metadatahdr), (uint32_t)ret, 0);
				}

				// Frame has been used, release the buffer space
				v2_rx_user_ready(ppd.raw);
				rx_ring->frame_num = (rx_ring->frame_num + 1) % rx_ring->req.tp_frame_nr;
			}
			
			if((ret!=FLOOD)&&(ret!=CONTROLLER)&&(ret!=DROP)){
				send(dataplane.ports[ret].fd, NULL, 0, MSG_DONTWAIT);
			}
			
			poll(Arg->pfd, 1, -1);
		
		sched_yield();
	}
	pthread_exit(NULL);
}

