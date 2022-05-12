#include <arpa/inet.h>
#include <errno.h>
#include <linux/errqueue.h>
#include <linux/filter.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>	//Provides declarations for ip header
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>	//For standard things
#include <stdlib.h>	//malloc
#include <string.h>     //memset
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#define MIN_COUNT 0
#define INFINITY_COUNT -1
#define MAX_IPV4_PACKET_SIZE 65535
#define ts_empty(ts) (!(ts)->tv_sec && !(ts)->tv_nsec)

#define SOF_TIMESTAMPING_RX SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE
#define SOF_TIMESTAMPING_RX_TX SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE

typedef unsigned long long		time_ns;

struct request_info {
	char *client_ip;
	uint16_t client_port;
	time_ns request_time;
	time_ns response_time;
	bool is_closed;
	
	struct request_info *next;
};

unsigned long dn2ip(char * dn);
void set_initial_request_info(struct request_info *, struct iphdr *, struct tcphdr *);
bool isAck(struct tcphdr *);
bool isSyncAck(struct tcphdr *);
time_ns gettime_ns(struct timespec *);
void handle_time(struct msghdr *, struct timespec *);
int enable_timestamping(int, bool);
void sigintHandler(int);
void write_info_to_file();
void free_mem(struct request_info *);
void help();

struct request_info *first = NULL;
struct timespec recv_time;

int main(int argc, char **argv) {

	char *interface = NULL;
	bool kernel_timestamps = true;
	unsigned long client_ip = 0;
	long request_count = INFINITY_COUNT;

	register int i;
	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			if(strlen(argv[i]) != 2){
				fprintf(stderr, "Command line error! What is \"%s\"???\n", argv[i]);
				help();
				exit(EXIT_FAILURE);
			}
			
			switch(argv[i][1]) {
				case 'h': {
					help();
					exit(EXIT_SUCCESS);
					break;
				}
				
				case 'p': {
					kernel_timestamps = false;
					break;
				}
				
				case 'c': {
					i++;
					if(i == argc){
						fprintf(stderr, "Parameter \"-c\" require a value.\n");
						help();
						exit(EXIT_FAILURE);
					}
					char * last_char;
					request_count = strtol(argv[i], &last_char, 10);
					if(errno == ERANGE || last_char[0] != '\0' || request_count <= MIN_COUNT){
						fprintf(stderr, "Invalid value of \"-c\" parameter.\n");
						help();
						exit(EXIT_FAILURE);
					}
					break;
				}
				
				case 'I': {
					i++;
					if(i==argc){
						fprintf(stderr, "Parameter \"-I\" require a value.\n");
						help();
						exit(EXIT_FAILURE);
					}
					size_t len = strlen(argv[i])+1;
					if(!len || len > IFNAMSIZ){
						fprintf(stderr, "Invalid value of \"-I\" parameter.\n");
						help();
						exit(EXIT_FAILURE);
					}
					interface=argv[i];
					break;
				}
				
				default: {
					fprintf(stderr, "Unknown parameter \"%s\"!\n", argv[i]);
					help();
					exit(EXIT_FAILURE);
				}
			}
		} else if (client_ip) {
			fprintf(stderr, "Command line error!\n");
			help();
			exit(EXIT_FAILURE);
		} else {
			client_ip = dn2ip(argv[i]);
		}
	}
	
	if (!client_ip) {
		fprintf(stderr, "You must specify the client ip address!\n");
		help();
		exit(EXIT_FAILURE);
	}
	
	if (!interface) {
		fprintf(stderr, "You must specify the interface!\n");
		help();
		exit(EXIT_FAILURE);
	}

	signal(SIGINT, sigintHandler);
	
	int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock_raw < 0) {
		fprintf(stderr, "Could not create socket. %m.\n");
		return EXIT_FAILURE;
	}
	
	if (setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface) + 1) < 0) {
	    perror("setsockopt bind device");
	    close(sock_raw);
	    return EXIT_FAILURE;
	}
	
	struct ifreq ethreq;
	strncpy(ethreq.ifr_name, interface, IF_NAMESIZE);
	if (ioctl(sock_raw, SIOCGIFFLAGS, &ethreq) == -1) {
	    perror("ioctl");
	    close(sock_raw);
	    exit(1);
	}
	ethreq.ifr_flags |= IFF_PROMISC;
	if (ioctl(sock_raw, SIOCSIFFLAGS, &ethreq) == -1) {
	    perror("ioctl");
	    close(sock_raw);
	    return EXIT_FAILURE;
	}
		
	struct sock_filter code[] = {
		{ 0x28, 0, 0, 0x0000000c },
		{ 0x15, 0, 5, 0x000086dd },
		{ 0x30, 0, 0, 0x00000014 },
		{ 0x15, 6, 0, 0x00000006 },
		{ 0x15, 0, 6, 0x0000002c },
		{ 0x30, 0, 0, 0x00000036 },
		{ 0x15, 3, 4, 0x00000006 },
		{ 0x15, 0, 3, 0x00000800 },
		{ 0x30, 0, 0, 0x00000017 },
		{ 0x15, 0, 1, 0x00000006 },
		{ 0x6, 0, 0, 0x00040000 },
		{ 0x6, 0, 0, 0x00000000 },
	};    
	struct sock_fprog bpf;
	bpf.len = sizeof(code)/sizeof(code[0]); 
	bpf.filter = code;


	if (setsockopt(sock_raw, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
		perror("setsockopt attach filter");
		close(sock_raw);
		return EXIT_FAILURE;
	}
	
	if(kernel_timestamps){
		if(interface){
			struct ifreq ifr;
			struct hwtstamp_config hwc;
			memset(&ifr,0, sizeof(ifr));
			memset(&hwc,0, sizeof(hwc));

			/* Standard kernel ioctl options */
			hwc.flags = 0;
			hwc.tx_type = HWTSTAMP_TX_ON;/*Enables hardware time stamping for outgoing packets*/
			hwc.rx_filter = HWTSTAMP_FILTER_ALL;/* time stamp any incoming packet */
			
			/* Interface name */
			strncpy (ifr.ifr_name, interface, sizeof (ifr.ifr_name));/*enp0s3(or ethx) */
			ifr.ifr_data = (char*)&hwc;

			int ok = ioctl(sock_raw, SIOCSHWTSTAMP, &ifr);
			if ( ok < 0 ) {
				fprintf(stderr, "Setting SIOCSHWTSTAMP ioctl failed %d (%d - %s)\n", ok, errno, strerror(errno));
			}
		}
		
		int flags = SOF_TIMESTAMPING_RX_SOFTWARE    /* software time stamping of incoming packets*/
				| SOF_TIMESTAMPING_TX_SOFTWARE  /* software time stamping  for outgoing packets*/
				| SOF_TIMESTAMPING_SOFTWARE     /* Enable reporting of software timestamps*/
				| SOF_TIMESTAMPING_RX_HARDWARE  /* hardware time stamping of incoming packets*/
				| SOF_TIMESTAMPING_TX_HARDWARE  /* hardware time stamping of outgoing packets*/
				| SOF_TIMESTAMPING_RAW_HARDWARE;/* Enable reporting of hardware timestamps*/

		if(enable_timestamping(sock_raw, true) < 0){
			fprintf(stderr, "ERROR: setsockopt SO_TIMESTAMPING.\n");
			return EXIT_FAILURE;
		}
	}
	
	struct request_info *current = NULL, *temp = NULL;
	
	int msg_size;
	struct msghdr msg;
	struct iovec iov;
	char control[1024];
	struct sockaddr_in recv_addr;
	char buffer[MAX_IPV4_PACKET_SIZE];
	
	struct iphdr *iph;
	struct tcphdr *tcph;
	
	if(!kernel_timestamps){
		if(setpriority(PRIO_PROCESS, 0/*this proc*/, -20)) {
			fprintf(stderr, "Setpriority error ocured! Maybe the program is not running as root? %m.\n");return EXIT_FAILURE;
		}
		struct sched_param param;
		param.sched_priority = sched_get_priority_max(SCHED_FIFO);
		if(sched_setscheduler(0/*this proc*/, SCHED_FIFO, &param)) {
			fprintf(stderr, "sched_setscheduler error ocured! %m.");
			return EXIT_FAILURE;
		}
	}
	
	while (1) {
		if (request_count == 0) break;
	
		memset (&msg, 0, sizeof(struct msghdr));
		memset (&iov, 0, sizeof(struct iovec));
		memset (control, 0, 1024);

		iov.iov_base = buffer;
		iov.iov_len = MAX_IPV4_PACKET_SIZE;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_name = &recv_addr;
		msg.msg_namelen = sizeof(struct sockaddr_in);
		msg.msg_control = control;
		msg.msg_controllen = 1024;
		
		msg_size = recvmsg(sock_raw, &msg, 0);
		
		if (msg_size < 0) {
			perror("recv error");
		}
		
		clock_gettime(CLOCK_REALTIME, &recv_time);
		
		if (kernel_timestamps) {
			handle_time(&msg, &recv_time);
		}
		
		// IP header from msg
		iph = (struct iphdr *)(msg.msg_iov->iov_base + sizeof(struct ethhdr));
		unsigned short iphdrlen = iph->ihl * 4;
		
		// 6 - TCP
		if (iph->protocol == 6) {
			// TCP header from msg
			tcph = (struct tcphdr*)(msg.msg_iov->iov_base + sizeof(struct ethhdr) + iphdrlen);
			
			if (iph->daddr == client_ip && isSyncAck(tcph)) {
				// Create new instance every SyncAck packet (Apache KeepAlive Timeout set to Off)
				// Every request -> new Sync
				if (!first) {
					first = (struct request_info *) malloc (sizeof (struct request_info));
					set_initial_request_info(first, iph, tcph);
					current = first;
				} else {
					temp = (struct request_info *) malloc (sizeof (struct request_info));
					set_initial_request_info(temp, iph, tcph);
					current->next = temp;
					current = current->next;
					temp = NULL;
				}
			} else if (current && current->is_closed) {
				// Request already processed, skip to next
				continue;
			} else if (iph->saddr == client_ip && isAck(tcph)) {
				// Update request time on new client -> server ACK
				current->request_time = gettime_ns(&recv_time);
			} else if (iph->daddr == client_ip && isAck(tcph)) {
				// Update response time and close on server -> client ACK
				current->response_time = gettime_ns(&recv_time);
				current->is_closed = true;
				request_count--;
			}
		}
	}
	
	close(sock_raw);
	write_info_to_file();
	free_mem(first);
	
	return EXIT_SUCCESS;
}

unsigned long dn2ip(char * dn) {
	unsigned long result=0;
	
	struct addrinfo hints;
	memset (&hints, 0,  sizeof(struct addrinfo));
	hints.ai_family=AF_INET;
	hints.ai_socktype=SOCK_RAW;
	hints.ai_protocol=IPPROTO_ICMP;
	
	struct addrinfo *res;
	int errcode=getaddrinfo(dn, NULL, &hints, &res);
	if(errcode==0){
		if(res->ai_addr->sa_family==AF_INET){
			result=((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
		}
		freeaddrinfo(res);
	}else{
		if(errcode==EAI_SYSTEM)fprintf(stderr, "Error of domain name resolution (system): %m.\n");
		else fprintf(stderr, "Error of domain name resolution: %s.\n", gai_strerror(errcode));
		exit(0);
	}
	
	return result;
}

void set_initial_request_info(struct request_info *info, struct iphdr *iph, struct tcphdr *tcph) {
	struct in_addr ip_addr;
	ip_addr.s_addr = iph->daddr;
	
	info->client_ip = inet_ntoa(ip_addr);
	info->client_port = ntohs(tcph->dest);
	info->request_time = 0;
	info->response_time = 0;
	info->is_closed = false;
	info->next = NULL;
}

bool isAck(struct tcphdr *tcph) {
	return !tcph->urg && tcph->ack && !tcph->psh && !tcph->rst && !tcph->syn && !tcph->fin;
}

bool isSyncAck(struct tcphdr *tcph) {
	return !tcph->urg && tcph->ack && !tcph->psh && !tcph->rst && tcph->syn && !tcph->fin;
}

time_ns gettime_ns(struct timespec *tp){
	return tp->tv_sec * 1000000000LL + tp->tv_nsec;
}

//****************************************************************************************************//
/*
*(extract the timestamps)get the timestamps hardware and software
*/
void handle_time(struct msghdr *msg, struct timespec *time)
{
	struct timespec *hard_time, *soft_time;
	struct scm_timestamping *tss = NULL;
	struct cmsghdr* cmsg;
	
	for( cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg,cmsg)){
		if( cmsg->cmsg_level != SOL_SOCKET ){continue;}
		switch( cmsg->cmsg_type ) {
			case SO_TIMESTAMPING:
				tss = (struct scm_timestamping *)CMSG_DATA(cmsg);
				break;
			default:
				break;
		}
	}
	
	/*
	* Timestamping are delivered in a SCM_TIMESTAMPING control message
	* containing 3 timestamps:
	* Most timestamps are passed in tss[0]
	* Hardware timestamps are passed in tss[2]
	*/
	if(tss){
		soft_time = tss->ts;
		hard_time = tss->ts+2;
		
		if (!ts_empty (hard_time)){
			time->tv_sec  = hard_time->tv_sec;
			time->tv_nsec = hard_time->tv_nsec;
		}else if (!ts_empty(soft_time)){
			time->tv_sec  = soft_time->tv_sec;
			time->tv_nsec = soft_time->tv_nsec;
		}
	}
}

int enable_timestamping(int sockfd, bool tx_enable){
	int flags = tx_enable?SOF_TIMESTAMPING_RX_TX:SOF_TIMESTAMPING_RX;
	return setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags));
}

void sigintHandler(int sig_num) {
	write_info_to_file();
	free_mem(first);
	exit(1);
}

void write_info_to_file() {
	if (first) {
		FILE *logfile = fopen("log.txt","w");
		if (logfile == NULL) printf("Unable to create file.");
		
		struct request_info *current = first;
		int i = 0;
		unsigned long long sum = 0;
		
		while (current) {
			i++;
			time_ns difference = current->response_time - current->request_time;
			sum += difference;
			fprintf(logfile, "\nRequest #%d\tClient IP: %s\tClient Port: %u\n", i, current->client_ip, current->client_port);
			fprintf(logfile, "Request: %lluns\tResponse: %lluns\tDifference: %lluns", current->request_time, current->response_time, difference);
			current = current->next;
		}
		
		fprintf(logfile, "\n\nAverage difference: %lluns\n", sum / i);
		
		fclose(logfile);
	}
}

void free_mem(struct request_info *node) {
	if (!node) return;
	
	free_mem(node->next);
	node->next = NULL;
	free(node);
}

void help() {
	printf("Usage: sniffer [-h] [-p] [-I] <client ip>\n");
	printf("\t-h\t| This help message.\n");
	printf("\t-p\t| Disable kernel timestamping.\n");
	printf("\t-I <interface>\t| Specify an interface for packet caprure and a hardware interface for for hardware timstamping.\n");
}

