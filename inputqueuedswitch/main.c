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
#include "multiAgent.h"
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
	
	srand(time(NULL));

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
    if((dataplane.dpid>>32)>0){//se o dataplane id tem mais de 32 bits
    	printf("Warning: dpid has more than 32 bits.\n");
    }
    dataplane.port_count = arguments.interface_count;
    dataplane.ports = calloc(dataplane.port_count, sizeof(struct port));
    //ISSO AQUI É PROVISÓRIO!!!!!!
    int nPartitions = 1;
    int totalNDataPath = 3;
    dataplane.ports[0].partitionId = 0;
    dataplane.ports[1].partitionId = 0;
    dataplane.ports[2].partitionId = 0;
    dataplane.ports[3].partitionId = 0;
    //////

    /* */

    // signal(SIGINT, sighandler);
    signal(SIGINT, voidhandler);
    signal(SIGKILL, sighandler);
	
    /* setup all the interfaces */
    printf("Setting up %d interfaces\n", dataplane.port_count);
    for (i = 0; i < dataplane.port_count; i++) {
        // Create the socket, allocate the tx and rx rings and create the frame io vectors
        setup_socket(&dataplane.ports[i], arguments.interfaces[i]);
        printf("Interface %s, index %d, fd %d\n", arguments.interfaces[i], i, dataplane.ports[i].fd);
    }
    printf("\n");
    
    printf("Creating %d datapaths.\n",totalNDataPath);
    
    ubpf_jit_fn* ubpf_fn = (ubpf_jit_fn*)malloc(nPartitions*sizeof(ubpf_jit_fn));
    struct agent_options* options = (struct agent_options*)malloc(
    	nPartitions*sizeof(struct agent_options));
	
	for (i = 0; i < nPartitions; i++) {
		options[i].dpid = dataplane.dpid + i<<32;//dataplane virtual para cada partição, para
		//facilitar a identificação do agente eBPF
		options[i].controller = arguments.controller;
	    agent_start(ubpf_fn+i, (tx_packet_fn)transmit, options+i, i, nPartitions);//ALTERAR ESSA FUNÇÃO TB
	}
	
	commonPathArg* cArg = (commonPathArg*) malloc(
		sizeof(commonPathArg)*totalNDataPath);
	
	if(cArg==NULL){
		printf("Error while allocating datapath registers");
	}
	
	pthread_t tid[totalNDataPath];
	
    switchCtrlReg* ctrl = createControlRegisters(totalNDataPath);
	
	for (i = 0; i < totalNDataPath; i++) {
		//preenchendo os campos da estrutura commonPathArg correspondente
		//a essa thread
        cArg[i].ctrl = ctrl;
        cArg[i].datapathId = i;
		cArg[i].ubpf_fn = ubpf_fn;//ponteiro das funções do agente eBPF (de cada agente)
		if(pthread_create(&(tid[i]), NULL, commonDataPath,&cArg[i])){
			printf("Error while creating a datapath.\n");
		}else{
			printf("Datapath created successfully.\n");
		}
		/*else if(!pthread_setschedprio(tid,99)){
			printf("Cannot set thread priority\n");
		}*/
	}
	
	//faz uma alocação inicial qualquer dos caminhos de dados
	for(i = 0; i < totalNDataPath; i++){
		ctrl->suggestedPort[i] = i;
		dataplane.ports[i].datapathId = i;
	}
	
	while (likely(!sigint)) {
		crossbarAnycast(ctrl);//determina quais portas serão processadas por quais caminhos de dados
	}
	
	for (i = 0; i < totalNDataPath; i++) {
		pthread_join(tid[i],NULL);
	}
	
	/* House keeping */
	
	free(cArg);
	free(ubpf_fn);
	
    agent_stop();
	
    printf("Terminating ...\n");
    for (i = 0; i < dataplane.port_count; i++) {
    	pthread_mutex_destroy((ctrl->mutex_forward_map)+i);
    	free(ctrl->forwardingMap[i]);
        teardown_socket(dataplane.ports+i);
    }
	
	pthread_mutex_destroy(&(ctrl->mutex_total_sum));
	free(ctrl->forwardingMap);
	free(ctrl->active);
	free(ctrl->suggestedPort);
	free(ctrl);
	
    return 0;
}
