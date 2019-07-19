#include <pcap.h>
#include <stdio.h>
#include<stdlib.h>
#include<stdint.h>

typedef struct ETHER{
    uint8_t Dmac[6];
    uint8_t Smac[6];
    uint8_t type[2];
}Ether;

typedef struct IP{
    uint8_t VHL;
    uint8_t Service[1];
    uint8_t Tlength[2];
    uint8_t id[2];
    uint8_t flag[2];
    uint8_t TTL[1];
    uint8_t proto;
    uint8_t checksum[2];
    uint8_t Sip[4];
    uint8_t Dip[4];
}IP;

typedef struct TCP{
    uint8_t Sport[2];
    uint8_t Dport[2];
    uint8_t trash[8];
    uint8_t length;

}TCP;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}
void Ethernet( Ether * ether){
    printf("ether.Dmac : %02X:%02X:%02X:%02X:%02X:%02X\n",
           ether->Dmac[0], ether->Dmac[1], ether->Dmac[2], ether->Dmac[3], ether->Dmac[4], ether->Dmac[5]);
    printf("ether.Smac : %02X:%02X:%02X:%02X:%02X:%02X\n",
           ether->Smac[0], ether->Smac[1], ether->Smac[2], ether->Smac[3], ether->Smac[4], ether->Smac[5]);

}
void IP_Print(IP *ip){
    printf("ip.Sip : %u.%u.%u.%u\n", ip->Sip[0],ip->Sip[1], ip->Sip[2],ip->Sip[3]);
    printf("ip.Dip : %u.%u.%u.%u\n", ip->Dip[0], ip->Dip[1], ip->Dip[2], ip->Dip[3]);

}
void TCP_Print(TCP *tcp){
    printf("Sport : %u\n", tcp->Sport[0] << 8 | tcp->Sport[1]);
    printf("Dport : %u\n", tcp->Dport[0] << 8  | tcp->Dport[1]);
}
int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage(); //error
    return -1;
  }

  char* dev = argv[1]; // buffer
  char errbuf[PCAP_ERRBUF_SIZE]; // err buffer
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); // input handle value

  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf); // if device name is wrong
    return -1; // error return
  }

  while (true) {

    struct pcap_pkthdr* header;
    const u_char* packet;
    Ether * ether;
    IP *ip;
    TCP *tcp;
    int data_length;

    const u_char* data;
    int i=0;
    int res = pcap_next_ex(handle, &header, &packet);

    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    ether = (Ether *)packet;
    ip = (IP *)(packet + 14);
    int ip_size = (ip->VHL & 0x0F) * 4;
    tcp  = (TCP  *)(packet + 14 + ip_size);
    int tcp_size = ((tcp->length & 0xf0) >> 4) * 4;
    data = (u_char *)(tcp + tcp_size);
    data_length = (ip->Tlength[0] << 8 | ip->Tlength[1]) - (ip_size + tcp_size);
    printf("===============================================================\n");


    if((ether->type[0] << 8 | ether->type[1] == 0x0800) && ip->proto == 0x06){ // ipv4

        Ethernet(ether);
        IP_Print(ip);
        TCP_Print(tcp);


            printf("data size : %u\n", data_length );

            if (data_length == 0)
                printf("No data");
            else if(data_length < 10)
                for(i=0; i<data_length; i++)
                    printf("%02X ", data[i]);
            else
                for(i=0; i<10; i++)
                    printf("%02X ", data[i]);

            printf("\n");
            printf("===============================================================\n");
        }



  }

  pcap_close(handle);
  return 0;
}
