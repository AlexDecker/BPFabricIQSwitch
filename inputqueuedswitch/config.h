#ifndef CONFIG_H
	#define CONFIG_H

	#define SIZE_DIVIDER 4 //threshold para send (tamanho ocupado do buffer)
	#define SEND_TIMEOUT 0.1 //timeout sem sends
	#define SEND_THRESHOLD_0 0.5 //probabilidade máxima para que ainda seja interessante chamar send
	#define MAXVAL_FORWARDINGMAP ~((unsigned int) 0) //utilizado na
	#define UPDATE_STATS 5 //atualiza as estatísticas apenas de 5 em 5 quadros

#endif
