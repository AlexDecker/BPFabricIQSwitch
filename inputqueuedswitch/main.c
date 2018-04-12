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
#include <argp.h>

#include <time.h>

#include "ubpf.h"
#include "agent.h"
#include "ebpf_consts.h"
#include "softswitch.h"

const char *argp_program_version = "ebpf-switch 0.1";
const char *argp_program_bug_address = "<simon.jouet@glasgow.ac.uk>";
static char doc[] = "eBPF-switch -- eBPF user space switch";
static char args_doc[] = "interface1 interface2 [interface3 ...]";

static void voidhandler(int num) {} // NOTE: do nothing prevent mininet from killing the softswitch

int main(int argc, char **argv)
{
    int i;

    /* Argument Parsing */
    struct arguments arguments;
    arguments.interface_count = 0;
    arguments.dpid = random_dpid();
    arguments.controller = "127.0.0.1:9000";
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    /* */
    dataplane.dpid = arguments.dpid;
    dataplane.port_count = arguments.interface_count;
    dataplane.ports = calloc(dataplane.port_count, sizeof(struct port));

    /* */
    struct pollfd pfds[dataplane.port_count];

    // signal(SIGINT, sighandler);
    signal(SIGINT, voidhandler);
    signal(SIGKILL, sighandler);

    /* setup all the interfaces */
    printf("Setting up %d interfaces\n", dataplane.port_count);
    for (i = 0; i < dataplane.port_count; i++) {
        // Create the socket, allocate the tx and rx rings and create the frame io vectors
        setup_socket(&dataplane.ports[i], arguments.interfaces[i]);

        // Create the array of pollfd for poll()
        pfds[i].fd = dataplane.ports[i].fd;
        pfds[i].events = POLLIN | POLLERR;
        pfds[i].revents = 0;

        //
        printf("Interface %s, index %d, fd %d\n", arguments.interfaces[i], i, dataplane.ports[i].fd);
    }
    printf("\n");

    /* */
    ubpf_jit_fn ubpf_fn = NULL;
    struct agent_options options = {
        .dpid = dataplane.dpid,
        .controller = arguments.controller
    };

    agent_start(&ubpf_fn, (tx_packet_fn)transmit, &options);

    //
    union frame_map ppd;

    while (likely(!sigint)) {
        //
        for (i = 0; i < dataplane.port_count; i++) {
            //
            struct ring *rx_ring = &dataplane.ports[i].rx_ring;

            // process all the packets received in the rx_ring
            while (v2_rx_kernel_ready(rx_ring->rd[rx_ring->frame_num].iov_base)) {
                ppd.raw = rx_ring->rd[rx_ring->frame_num].iov_base;

                // printf("metadatahdr len %lu\n", sizeof(struct metadatahdr)); // Should be  ppd.v2->tp_h.tp_mac - TPACKET2_HDRLEN

                /**/
                struct metadatahdr *metadatahdr = (struct metadatahdr *)((uint8_t *)ppd.raw + TPACKET2_HDRLEN);
                metadatahdr->in_port = i;
                metadatahdr->sec = ppd.v2->tp_h.tp_sec;
                metadatahdr->nsec = ppd.v2->tp_h.tp_nsec;
                metadatahdr->length = (uint16_t)ppd.v2->tp_h.tp_len;

                /* Here we have the packet and we can do whatever we want with it */
                if (ubpf_fn != NULL) {
                    uint64_t ret = ubpf_fn(metadatahdr, ppd.v2->tp_h.tp_len + sizeof(struct metadatahdr));
                    // printf("bpf return value %lu\n", ret);
                    transmit(metadatahdr, ppd.v2->tp_h.tp_len + sizeof(struct metadatahdr), (uint32_t)ret, 0);
                }

                // Frame has been used, release the buffer space
                v2_rx_user_ready(ppd.raw);
                rx_ring->frame_num = (rx_ring->frame_num + 1) % rx_ring->req.tp_frame_nr;
            }
        }

        // Send all the pendings packets for each interface
        for (i = 0; i < dataplane.port_count; i++) {
            send(dataplane.ports[i].fd, NULL, 0, MSG_DONTWAIT); // Should we use POLLOUT and just queue the messages to transmit then call send() once
        }

        // Poll for the next socket POLLIN or POLLERR
        poll(pfds, dataplane.port_count, -1);
    }

    /* House keeping */
    agent_stop();
    printf("Terminating ...\n");
    for (i = 0; i < dataplane.port_count; i++) {
        teardown_socket(&dataplane.ports[i]);
    }

    return 0;
}
