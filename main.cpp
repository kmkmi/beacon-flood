#include <pcap.h>
#include <stdio.h>
#include <cstring>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "main.h"
#include <map>
#include <unistd.h>
#include <vector>
#include <string>



std::vector<std::string> ssid_list;



void usage() {
    printf("syntax : beacon-flood <interface> <ssid-list-file>\n");
    printf("sample : beacon-flood mon0 ssid-list.txt\n");
}


char* hex(u_int8_t *addr, char* buf, int size)
{

    for(int i=0;i<size;i++)
    {
        snprintf(buf+(3*i),size, "%02x",addr[i]);
        if(i!=size-1)
            snprintf(buf+2+(3*i),2,":");

    }

    return buf;

}





beacon_packet* getBeaconPacket(std::string ssid ){

    beacon_packet* bpkt = (beacon_packet*)malloc(sizeof(beacon_packet));
    bpkt->rtap.header_revision = 0x0;
    bpkt->rtap.header_pad = 0x0;
    bpkt->rtap.header_length = 0x0c;
    bpkt->rtap.present_flags[0] = 0x00000000;
    bpkt->rtap.present_flags[1] = 0x00000000;


    bpkt->dot11_frame.frame_control_field.init(0x8000);
    bpkt->dot11_frame.duration = 0x0000;

    Mac apMac = Mac("12:34:56:78:9a:be");
    bpkt->dot11_frame.mac1 = Mac("ff:ff:ff:ff:ff:ff");
    bpkt->dot11_frame.mac2 = apMac;
    bpkt->dot11_frame.mac3 = apMac;
    bpkt->dot11_frame.fragment_number = 0b0;
    bpkt->dot11_frame.sequence_number = 0b0;

    memset(bpkt->dot11_wlan.fixed_parameters, 0, 12);
    bpkt->dot11_wlan.fixed_parameters[10] = 0x01;
    bpkt->dot11_wlan.tag_length = ssid.length()-1;
    strncpy(bpkt->dot11_wlan.ssid, ssid.c_str(), ssid.length());

    char buf[512];
    printf("%s\n",hex((u_int8_t*)bpkt,buf, sizeof(beacon_packet)-(MAX_SSID_LEN-ssid.size())-1) );

    return bpkt;
}


int main(int argc, char* argv[]) {

    if (argc != 3) {

        usage();
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    FILE* fp;

    if((fp= fopen(argv[2], "r")) == NULL){
        printf("File open failed!\n");
        return -1;
    }
    char buf[MAX_SSID_LEN+1];
    while(!feof(fp)){
        if(!fgets(buf, MAX_SSID_LEN, fp))
            break;
        ssid_list.push_back(std::string(buf).substr(0,-1));

    }
    fclose(fp);

    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", argv[1], errbuf);
        return -1;
    }



    beacon_packet **packet = (beacon_packet**)malloc(sizeof(beacon_packet*)*ssid_list.size());





    for(unsigned int i = 0; i<ssid_list.size(); i++){

        packet[i] = getBeaconPacket(ssid_list[i]);

    }

    int res;



    for(int i = 0;; i++){
        usleep(100000);
        res = pcap_sendpacket(handle, reinterpret_cast<const u_int8_t*>(packet[i%ssid_list.size()]),
                sizeof(beacon_packet)-(MAX_SSID_LEN-ssid_list[i%ssid_list.size()].size())-1);
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        printf("Beacon Packet Sended.\n");
    }


    pcap_close(handle);


    for(unsigned int i = 0; i<ssid_list.size(); i++){
        free(packet[i]);
    }
    free(packet);





}
