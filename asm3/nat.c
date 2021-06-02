#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h> // required by "netfilter.h"
#include <arpa/inet.h> // required by ntoh[s|l]()
#include <signal.h> // required by SIGINT
#include <string.h> // required by strerror()
#include <sys/time.h> // required by gettimeofday()
#include <time.h> // required by nanosleep()
#include <errno.h> // required by errno
#include <pthread.h>
#include <netinet/ip.h>        // required by "struct iph"
#include <netinet/tcp.h>    // required by "struct tcph"
#include <netinet/udp.h>    // required by "struct udph"
#include <netinet/ip_icmp.h>    // required by "struct icmphdr"
#include <linux/netfilter.h> // required by NF_ACCEPT, NF_DROP, etc...
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "checksum.h"   //for checksum
#define BUF_SIZE 1500
#define PORT_RANGE 10000
typedef struct udp_table{
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t tran_ip;
    uint16_t tran_port;
    time_t time;
    struct udp_table *next;
}UDP_Table;


UDP_Table *nat_table = NULL;

char *subnet_mask;
char *inputLAN;
int bucket_size;
int fill_rate;
int num_pkt;
int num_inbound;
int num_outbound;
unsigned int local_mask;
unsigned int publicIP;
int ports[2001]={0};
int num_token;
double _time_stamp;
double _now;
double wait_time;
struct nfq_data *pkt_buffer[10]={NULL};    
struct nfq_q_handle *pthread_queue[10]={NULL};  
pthread_mutex_t pthread_process;



void check_time();
UDP_Table *find_inbound(unsigned int port);
UDP_Table *find_outbound(unsigned int port,unsigned int ip);

void showTable();

UDP_Table *find_inbound(unsigned int port)
{
    UDP_Table *cur_entry = NULL;
    if(nat_table==NULL) return NULL;
    cur_entry=nat_table;
    while(cur_entry != NULL){
        if(cur_entry->tran_port == port) return cur_entry;
        cur_entry=cur_entry->next;
    }
    return NULL;
}

UDP_Table *find_outbound(unsigned int port,unsigned int ip)
{
    UDP_Table *cur_entry = NULL;
    if(nat_table==NULL) return NULL;
    cur_entry=nat_table;
    while(cur_entry != NULL){
        if((cur_entry->src_port == port) && (cur_entry->src_ip) == ip) return cur_entry;
        cur_entry=cur_entry->next;
    }
    return NULL;
}

void showTable()
{
    printf("NAT table:\n");
    printf("  source IP - Port  |  translated IP - Port\n");

    UDP_Table *cur=nat_table;
    while(cur != NULL){
        struct in_addr tmp;
        tmp.s_addr = htonl(cur->src_ip);
        printf(" (%s , %d) ",(char*)inet_ntoa(tmp),cur->src_port);
        tmp.s_addr = htonl(cur->tran_ip);
        printf(" (%s , %d) ",(char*)inet_ntoa(tmp),cur->tran_port);
        printf("\n");
        cur=cur->next;
    }
}
int findport()
{
  int i;
  for(i = PORT_RANGE;i <= 12000; i++){
    if(!ports[i-PORT_RANGE]){
      ports[i-PORT_RANGE]=1;
      return i;
    }
  }
  return -1;
}


static int Callback(struct nfq_q_handle *myQueue, struct nfgenmsg *msg,
    struct nfq_data *pkt, void *cbData) {
  int i;
  int flag=0;
  for(i=0;i<10;i++)
  {
    if(pkt_buffer[i]==NULL){
      pthread_mutex_lock(&pthread_process);
      flag=1;
      pkt_buffer[i]=pkt; 
      pthread_queue[i]=myQueue;
      pthread_mutex_unlock(&pthread_process);
      break;
    }
  }
  if(!flag){
    unsigned int id = 0;

    struct nfqnl_msg_packet_hdr *ph;
    if ((ph = nfq_get_msg_packet_hdr(pkt))) {
      id = ntohl(ph->packet_id);
    }
    return nfq_set_verdict(myQueue, id, NF_DROP, 0, NULL);
  }
  else
  {
    return 1;
  }
  
}

double get_time(){ // in ms
  struct timeval t;
  gettimeofday(&t, NULL);
  return t.tv_sec * 1000 + (t.tv_usec) / 1000;
}


int token_generate(){
  int tokens = 0;
	//https://scriptbucket.wordpress.com/2012/01/01/token-bucket-algorithm-in-c/  
	_now = get_time();
	int time_diff = ((int)(_now - _time_stamp) / 1000);
	//combine GetToken with ConsumeToken
	if(time_diff){
	  num_token += fill_rate * time_diff;
	  _time_stamp = get_time();
	  if(num_token >= bucket_size){
		num_token = bucket_size;
		_now = get_time();
	  }
	}
  if(num_token > 1){
    num_token--;
    tokens = 1;
  }
  printf("%d token\n", num_token);
  return tokens;
  
}

void *pthread_prog()
{
  while(1)
  {
    int i;
    for(i=0;i<10;i++)
    {
      if(pkt_buffer[i]!=NULL)
      {
        pthread_mutex_lock(&pthread_process);
        struct nfq_data *pkt=pkt_buffer[i];
        pkt_buffer[i]=NULL;
        struct nfq_q_handle *myQueue=pthread_queue[i];
        pthread_queue[i]=NULL;
		
        pthread_mutex_unlock(&pthread_process);

        unsigned int id = 0;
        unsigned char *pktData;
        int packet_len;
		struct iphdr *ip;
        struct nfqnl_msg_packet_hdr *ph;
		
        ph = nfq_get_msg_packet_hdr(pkt);
        id = ntohl(ph->packet_id);
        packet_len = nfq_get_payload(pkt, &pktData);
        ip = (struct iphdr *)pktData;
        
        if (ip->protocol != IPPROTO_UDP) {
          printf("NON UDP protocol!\n");
          nfq_set_verdict(myQueue, id, NF_DROP, 0, NULL);
          continue;
        }
		  struct timespec t1, t2;
		  t1.tv_sec = 0;
		  t1.tv_nsec = 5000;
		  while(!token_generate()){
			if(nanosleep(&t1, &t2) < 0){
			  printf("ERROR: nanosleep() system call failed!\n");
			  exit(1);
			}
		  }
		 UDPHandling(myQueue,id, packet_len,pktData, ip);

      }
    }

    usleep(10);
  }
  pthread_exit(NULL);
}

void UDPHandling(struct nfq_q_handle *myQueue,unsigned int id,int packet_len,unsigned char *pktData, struct iphdr *ip)
{
        uint32_t src_ip;
        uint32_t dest_ip;
		uint16_t src_port;
        uint16_t dest_port;
		struct udphdr *udph;
		
		src_ip = ntohl(ip->saddr);
        dest_ip = ip->daddr;

        udph=(struct udphdr*)(((char*)ip) + ip->ihl*4);

		src_port=ntohs(udph->source);
		dest_port=ntohs(udph->dest);
		
        int mask_int = atoi(subnet_mask);
        unsigned int local_mask= 0xffffffff << (32 - mask_int);
        struct in_addr tmp;
        inet_aton(inputLAN, &tmp);
        uint32_t local_network = ntohl(tmp.s_addr) & local_mask;

        if((src_ip & local_mask) == local_network)
        {
          //outbound
          UDP_Table *finder=find_outbound(src_port,src_ip);
          unsigned int new_ip;
          unsigned int new_port;
          if(finder == NULL)
          {
            unsigned int trans_port = findport();
            if(trans_port == -1)
            {
              printf("no available port any more!\nbye bye!\nsee you!\ndont come back!\n:-P\n");
              exit(-1);
            }
            new_ip = publicIP;
            new_port = trans_port;
	    UDP_Table *tmp=(UDP_Table*) malloc(sizeof(UDP_Table));
            tmp->src_ip = src_ip;
            tmp->src_port = src_port;
            tmp->tran_port = trans_port;
            tmp->tran_ip = publicIP;
            tmp->time=time(NULL);
    	    tmp->next=nat_table;
   	    nat_table=tmp;
  	    showTable();
		ip->saddr = htonl(new_ip);
          udph->source = htons(new_port);
          udph->check=udp_checksum(pktData);
          ip->check=ip_checksum(pktData);
          nfq_set_verdict(myQueue, id, NF_ACCEPT, packet_len, pktData);
		  num_pkt += 1;
           }
          else
          {
            new_ip=publicIP;
            new_port=finder->tran_port;
            finder->time=time(NULL);
			struct in_addr src_tmp, tran_tmp, dest_tmp;
			num_outbound += 1;
			tran_tmp.s_addr = htonl(publicIP);
			ip->saddr = htonl(new_ip);
          udph->source = htons(new_port);
          udph->check=udp_checksum(pktData);
          ip->check=ip_checksum(pktData);
          nfq_set_verdict(myQueue, id, NF_ACCEPT, packet_len, pktData);
		  num_pkt += 1;
		  src_tmp.s_addr = htonl(finder->src_ip);
		  dest_tmp.s_addr = htonl(ntohl(ip->daddr));
		  printf("Received packet: id=%d, ts=%lf\n", num_pkt,get_time());
		  printf("Is UDP 17\n");
		  printf("udp_translate() : src[%s:%d], dest[%d.%d.%d.%d:%u] inbound %d, outbound %d\n", (char*)inet_ntoa(src_tmp), finder->src_port, dest_ip & 0xff, (dest_ip >> 8) & 0xff,(dest_ip >> 16) & 0xff, (dest_ip >> 24) & 0xff,(unsigned int)ntohs(udph->dest), num_inbound, num_outbound );
          printf("\t[OUT BOUND]\ttranslate src [%s:%d] ->",(char*)inet_ntoa(src_tmp), finder->src_port);
		  printf(" [%s:%d]\n\n", (char*)inet_ntoa(tran_tmp), finder->tran_port);
          }
          
        }
        else
        {
          //inbound
          UDP_Table *finder = find_inbound(dest_port);
          if(finder != NULL)
          {
            finder->time=time(NULL);
            ip->daddr = htonl(finder->src_ip);
            udph->dest = htons(finder->src_port);


            udph->check = udp_checksum(pktData);
            ip->check = ip_checksum(pktData);
			struct in_addr src_tmp, tran_tmp, dest_tmp;
			num_inbound += 1;
			tran_tmp.s_addr = htonl(publicIP);
			
		  src_tmp.s_addr = htonl(finder->src_ip);
		  dest_tmp.s_addr = htonl(ntohl(ip->daddr));
		  printf("Received packet: id=%d, ts=%lf\n", num_pkt,get_time());
		  printf("Is UDP 17\n");
		  printf("udp_translate() : src[%d.%d.%d.%d:%u], dest[%s:%d] inbound %d, outbound %d\n",  ip->saddr & 0xff, (ip->saddr >> 8) & 0xff,(ip->saddr >> 16) & 0xff, (ip->saddr >> 24) & 0xff,(unsigned int)ntohs(udph->source),(char*)inet_ntoa(tran_tmp), finder->tran_port , num_inbound,num_outbound);
          printf("\t[IN BOUND]\ttranslate src [%s:%d] ->",(char*)inet_ntoa(tran_tmp), finder->tran_port);
		  printf(" [%s:%d]\n\n", (char*)inet_ntoa(src_tmp), finder->src_port);
            nfq_set_verdict(myQueue, id, NF_ACCEPT, packet_len, pktData);
			num_pkt += 1;
          }
          else
          {
            nfq_set_verdict(myQueue, id, NF_DROP, 0, NULL);
          }
        }
}



int main(int argc, char** argv) {
   
  if(argc != 6){
    fprintf(stderr, "Usage sudo ./nat <IP> <LAN> <MASK> <bucket size> <fill rate>");
    exit(1);
  }
	num_pkt = 0;
	num_inbound = 0;
	num_outbound = 0;
  pthread_mutex_init(&pthread_process,NULL);

  // Get a queue connection handle from the module
  struct nfq_handle *nfqHandle;
  if (!(nfqHandle = nfq_open())) {
    printf("Error in nfq_open()\n");
    exit(-1);
  }

  // Unbind the handler from processing any IP packets
  if (nfq_unbind_pf(nfqHandle, AF_INET) < 0) {
    printf("Error in nfq_unbind_pf()\n");
    exit(1);
  }

  // Install a callback on queue 0
  struct nfq_q_handle *nfQueue;
  if (!(nfQueue = nfq_create_queue(nfqHandle,  0, &Callback, NULL))) {
    printf("Error in nfq_create_queue()\n");
    exit(1);
  }
  // nfq_set_mode: I want the entire packet 
  if(nfq_set_mode(nfQueue, NFQNL_COPY_PACKET, BUF_SIZE) < 0) {
    printf("Error in nfq_set_mode()\n");
    exit(-1);
  }

  struct nfnl_handle *netlinkHandle;
  netlinkHandle = nfq_nfnlh(nfqHandle);


  inputLAN = argv[2];
  subnet_mask = argv[3];
  bucket_size = atoi(argv[4]);
  fill_rate = atoi(argv[5]);
  num_token = bucket_size;
  _time_stamp = get_time();

  struct in_addr tmp;
  inet_aton(argv[1],&tmp);
  publicIP = ntohl(tmp.s_addr);
  int fd;
  fd = nfnl_fd(netlinkHandle);

  int res;
  char buf[BUF_SIZE];

  pthread_t handle;
  if(pthread_create(&handle,NULL,pthread_prog, NULL))
  {
    printf("Fail to create pthread_prog!\n");
    exit(-1);
  }


  while((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0){
	  time_t now_time=time(NULL);
      int new_connect=0;
      struct timespec t1, t2;
      UDP_Table *current = nat_table;
      UDP_Table *prev = NULL;
    
	  UDP_Table *finder;
  t1.tv_sec = 0;
  t1.tv_nsec = 5000;
  if(!token_generate()){
    if(nanosleep(&t1, &t2) < 0){
      printf("ERROR: nanosleep() system call failed!\n");
      exit(1);
    }
    token_generate();
  }
    if(nat_table!=NULL)
    {
        while(current !=NULL){
            if(difftime(now_time,current->time) >= 10.0){
                if(current->next == NULL){
                    if(nat_table == current){
                        free(current);
                        nat_table=NULL;
                        current=NULL;
                    }else{
                        free(current);
                        prev->next=NULL;
                        current=NULL;
                    }
                }else{
                    if(nat_table==current){
                        nat_table=current->next;
                        free(current);
                        current=nat_table;
                    }else{
                        prev->next=current->next;
                        free(current);
                        current=prev->next;
                    }
                }
	     new_connect=1;
            }else{
                prev=current;
                current=prev->next;
            }
        }
        if(new_connect == 1)
            showTable();    
    }

  for(int i = PORT_RANGE;i <= 12000; i++){
    if(ports[i-PORT_RANGE]==1){
      if(find_inbound((unsigned int)i) == NULL)
        ports[i-PORT_RANGE]=0;
    }
  }
      nfq_handle_packet(nfqHandle, buf, res);
  }
  pthread_mutex_destroy(&pthread_process);

  nfq_destroy_queue(nfQueue);
  nfq_close(nfqHandle);


  return 0;
}
