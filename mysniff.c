#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //memset
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>
#include <netinet/ether.h>
#include <net/if.h>


int sock_raw;
FILE *logfile;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
struct sockaddr_in source,dest;
void print_eth_header(unsigned char * Buffer,int Size){
  struct  ether_header * eth =(struct ether_header *) Buffer;
  printf("%x\n",eth->ether_dhost[1] );
  fprintf(logfile, "Mac:");
  fprintf(logfile, "Source Mac:%x.",eth->ether_shost[0] );
  fprintf(logfile, "%x.",eth->ether_shost[1] );
  fprintf(logfile, "%x.",eth->ether_shost[2] );
  fprintf(logfile, "%x.",eth->ether_shost[3] );
  fprintf(logfile, "%x.",eth->ether_shost[4] );
  fprintf(logfile, "%x , ",eth->ether_shost[5] );
  fprintf(logfile, "Destination Mac:%x.",eth->ether_dhost[0] );
  fprintf(logfile, "%x.",eth->ether_dhost[1] );
  fprintf(logfile, "%x.",eth->ether_dhost[2] );
  fprintf(logfile, "%x.",eth->ether_dhost[3] );
  fprintf(logfile, "%x.",eth->ether_dhost[4] );
  fprintf(logfile, "%x \n",eth->ether_dhost[5] );
}
void print_ip_header(unsigned char* Buffer, int Size)
{

   struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ether_header));


   memset(&source, 0, sizeof(source));
   source.sin_addr.s_addr = iph->saddr;

   memset(&dest, 0, sizeof(dest));
   dest.sin_addr.s_addr = iph->daddr;

   fprintf(logfile,"IP:");
   fprintf(logfile,"Source IP: %s , ",inet_ntoa(source.sin_addr));
   fprintf(logfile,"Destination IP: %s , ",inet_ntoa(dest.sin_addr));
   fprintf(logfile,"Checksum : %d , ",ntohs(iph->check));
   fprintf(logfile,"Protocol : %d , ",(unsigned int)iph->protocol);
   fprintf(logfile,"TTL: %d , ",(unsigned int)iph->ttl);
   fprintf(logfile, "ID: %d , ",ntohs(iph->id) );
   fprintf(logfile, "Fragment offset : %d \n", ntohs(iph->frag_off));
}

void print_udp_packet(unsigned char *Buffer , int Size)
{

   unsigned short iphdrlen;

   struct iphdr *iph = (struct iphdr *)Buffer;
   iphdrlen = iph->ihl*4;

   struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen + sizeof(struct ether_header));
   print_eth_header(Buffer,Size);
   print_ip_header(Buffer,Size);

   fprintf(logfile,"UDP:");
   fprintf(logfile,"Source Port : %d , " , ntohs(udph->source));
   fprintf(logfile,"Destination Port : %d , " , ntohs(udph->dest));
   fprintf(logfile,"UDP Checksum : %d , " , ntohs(udph->check));
   fprintf(logfile,"UDP Length : %d\n" , ntohs(udph->len));
   fprintf(logfile,"###########################################################\n");
}
void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ether_header));

      print_eth_header(Buffer,Size);
      print_ip_header(Buffer,Size);
    fprintf(logfile, "TCP:");
    fprintf(logfile,"Source Port: %u , ",ntohs(tcph->source));
    fprintf(logfile,"Destination Port : %u , ",ntohs(tcph->dest));
    fprintf(logfile,"Sequence Number: %u , ",ntohl(tcph->seq));
    fprintf(logfile,"Acknowledge Number : %u , ",ntohl(tcph->ack_seq));
    fprintf(logfile,"Window Size : %d , ",ntohs(tcph->window));
    fprintf(logfile,"Checksum   : %d ,  ",ntohs(tcph->check));
    fprintf(logfile,"Synchronise Flag   : %d , ",(unsigned int)tcph->syn);
    fprintf(logfile,"Finish Flag     : %d , ",(unsigned int)tcph->fin);
    fprintf(logfile,"Urgent Flag    : %d , ",(unsigned int)tcph->urg);
    fprintf(logfile,"Acknowledgement Flag : %d , ",(unsigned int)tcph->ack);
    fprintf(logfile,"Reset Flag   : %d , ",(unsigned int)tcph->rst);
    fprintf(logfile, "Data Offset : %d \n",(unsigned int)tcph->doff *4 );
    fprintf(logfile, "########################################################################################\n");
}
void print_icmp_packet(unsigned char* Buffer , int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;

    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen + sizeof(struct ether_header));
    print_eth_header(Buffer,Size);
    print_ip_header(Buffer , Size);
    fprintf(logfile,"ICMP:");
    fprintf(logfile,"Type : %d , ",(unsigned int)(icmph->type));
    fprintf(logfile,"Code : %d , ",(unsigned int)(icmph->code));
    fprintf(logfile,"Checksum : %d\n",ntohs(icmph->checksum));
    fprintf(logfile,"###########################################################\n");
}


void ProcessPacket(unsigned char* buffer, int size){
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ether_header));
    printf("hi\n" );
    switch (iph->protocol)
    {
      case 6:  //TCP Protocol
        print_tcp_packet(buffer,size);
        break;
      case 17: //UDP Protocol
        print_udp_packet(buffer,size);
        break;
      case 1:  //ICMP Protocol
        print_icmp_packet(buffer,size);
        break;

    }

}
int main()
{
   int saddr_size , data_size;
   struct sockaddr saddr;
   struct in_addr in;

   unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!

   logfile=fopen("log.txt","w");
   if(logfile==NULL) printf("Unable to create file.");
   printf("Starting...\n");
   //Create a raw socket that shall sniff
   sock_raw = socket( PF_PACKET, SOCK_RAW, htons( ETH_P_ALL ) );
   if(sock_raw < 0)
   {
       printf("Socket Error\n");
       return 1;
   }
   while(1)
   {
       saddr_size = sizeof saddr;
       data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
       if(data_size <0 )
       {
           printf("Recvfrom error , failed to get packets\n");
           return 1;
       }
       ProcessPacket(buffer , data_size);
   }
   close(sock_raw);
   printf("Finished");
   return 0;
}
