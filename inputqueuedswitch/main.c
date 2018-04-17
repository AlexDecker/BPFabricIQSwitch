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
#include <pthread.h>

#include <time.h>

#include "ubpf.h"
#include "agent.h"
#include "ebpf_consts.h"
#include "softswitch.h"
#include "switchFabric.h"

const char *argp_program_version = "ebpf-switch 0.1";
const char *argp_program_bug_address = "<simon.jouet@glasgow.ac.uk>";
static char doc[] = "eBPF-switch -- eBPF user space switch";
static char args_doc[] = "interface1 interface2 [interface3 ...]";

static struct argp_option options[] = {
    {"verbose",  'v',      0,      0, "Produce verbose output" },
    {"dpid"   ,  'd', "dpid",      0, "Datapath id of the switch"},
    {"controller", 'c', "address", 0, "Controller address default to 127.0.0.1:9000"},
    { 0 }
};

#define MAX_INTERFACES 255

struct arguments
{
    char *interfaces[MAX_INTERFACES];
    int interface_count;
    unsigned long long dpid;
    char *controller;

    int verbose;
};

static error_t
parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = state->input;

    switch (key)
    {
        case 'v':
            arguments->verbose = 1;
            break;

        case 'd':
            arguments->dpid = strtoull(arg, NULL, 10);
            break;

        case 'c':
            arguments->controller = arg;
            break;

        case ARGP_KEY_ARG:
            arguments->interfaces[state->arg_num] = arg;
            arguments->interface_count++;
            break;

        case ARGP_KEY_END:
            if (state->arg_num < 1) /* Not enough arguments. */
                argp_usage (state);
            break;

        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };


static void voidhandler(int num) {} // NOTE: do nothing prevent mininet from killing the softswitch

sig_atomic_t sigint;//definição

void sighandler(int num){sigint = 1;}

int main(int argc, char **argv){

	sigint = 0;//agora é extern, então a definição no ato de declaração causa conflitos.	
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
    struct pollfd* pfds = (struct pollfd*) malloc(
		sizeof(struct pollfd)*dataplane.port_count);

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
    //ubpf_jit_fn* ubpf_fn = (ubpf_jit_fn*)malloc(dataplane.port_count*sizeof(ubpf_jit_fn));
    ubpf_jit_fn* ubpf_fn = (ubpf_jit_fn*)malloc(sizeof(ubpf_jit_fn));
    
    struct agent_options options = {
        .dpid = dataplane.dpid,
        .controller = arguments.controller
    };
	
	/*for (i = 0; i < dataplane.port_count; i++) {
	    agent_start(ubpf_fn+i, (tx_packet_fn)transmit, &options);
	}*/
	
	agent_start(ubpf_fn, (tx_packet_fn)transmit, &options);
	
	commonPathArg* cArg = (commonPathArg*) malloc(
		sizeof(commonPathArg)*dataplane.port_count);
	
	if(cArg==NULL){
		printf("Error while allocating datapath registers");
	}
	
	pthread_t tid;
	
    switchCtrlReg* ctrl = createControlRegisters();
	
	for (i = 0; i < dataplane.port_count; i++) {
		//preenchendo os campos da estrutura commonPathArg correspondente
		//a essa thread
        cArg[i].ctrl = ctrl;
		cArg[i].portNumber = i;
		cArg[i].imReady = false;
		cArg[i].pfd = pfds+i;
		//cArg[i].ubpf_fn = ubpf_fn+i;//ponteiro da função do agente eBPF
		cArg[i].ubpf_fn = ubpf_fn;//ponteiro da função do agente eBPF
		//criando a thread responsável por esta porta de entrada
		if(pthread_create(&tid, NULL, commonDataPath,&cArg[i])){
			printf("Error while creating a common datapath.\n");
		}
	}
	
	//cria a thread com o caminho de dados principal
	mainPathArg* mArg = (mainPathArg*) malloc(sizeof(mainPathArg));
    mArg->ctrl = ctrl;
	mArg->nPorts = dataplane.port_count;
	mArg->allCommonPaths = cArg;
	mArg->pfds = pfds;
    if(pthread_create(&tid, NULL, mainBPFabricPath, mArg)){
    	printf("Error while creating the main datapath.\n");
    }

    /*while (likely(!sigint)) {
        //
        for (i = 0; i < dataplane.port_count; i++) {
            //
            datapathEngine(cArg+i);
            
        }
        
        // Send all the pendings packets for each interface
        for (i = 0; i < dataplane.port_count; i++) {
            send(dataplane.ports[i].fd, NULL, 0, MSG_DONTWAIT);
			//poll(pfds+i, 1, -1);
        }

        // Poll for the next socket POLLIN or POLLERR
        poll(pfds, dataplane.port_count, -1);
    }*/

    /* House keeping */
	pthread_exit(NULL);
	free(cArg);
	free(mArg);
	free(pfds);
	free(ubpf_fn);
	pthread_mutex_destroy(&(ctrl->mutex));
    agent_stop();
	
    printf("Terminating ...\n");
    for (i = 0; i < dataplane.port_count; i++) {
        teardown_socket(&dataplane.ports[i]);
    }

    return 0;
}
