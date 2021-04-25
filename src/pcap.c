#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include "standard.h"



int main(int argc, char *argv[]){
    if(argc<1){
        printf("not enough arguments \n");
    }
    char *device;
    device = argv[1];
    char *filter;
    filter = (char *)malloc(BUFF_SIZE*sizeof(char));
    filter = "port 80";
    if(strcmp(device, "default")==0){
        device = get_default();
    }
    else{
        printf("Device: %s \n", device);
    }       
    bpf_u_int32 net;
    bpf_u_int32 mask;

    get_device_details(device,net,mask);
    printf("ip:%d, netmask:%d \n",net,mask);

    pcap_t *handle;
    handle = get_handle(device);
    struct pcap_pkthdr header;
    const u_char *packet;
    packet = pcap_next(handle, &header);
    printf("packet found: %s \n", header.comment);

}

char *get_default(){
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    dev = pcap_lookupdev(errbuf);
    if(!dev){
        fprintf(stderr, "Could not find default device: %s \n", errbuf);
        exit(EXIT_FAILURE);
    }
    printf("Device: %s \n", dev);
    return dev;
}

pcap_t *get_handle(char *device){
    pcap_t *handle;
    handle = (pcap_t *)malloc(sizeof(pcap_t *));
    if(!handle){
        fprintf(stderr, "memory allocation error \n");
        exit(EXIT_FAILURE);
    }
    if(!device){
        fprintf(stderr, "missing device name \n");
        exit(EXIT_FAILURE);
    }
    char *error;
    error = (char *)malloc(sizeof(char)*BUFF_SIZE);
    handle = pcap_open_live(device,BUFF_SIZE,1,10,error);
    if(handle==NULL){
        fprintf(stderr,"Error opening handle %s \n",error);
        exit(EXIT_FAILURE);
    }
    return handle;
}   

void get_device_details(char *device, bpf_u_int32 net, bpf_u_int32 mask){
    if(!device){
        fprintf(stderr,"invalid device name \n");
        exit(EXIT_FAILURE);
    }
    char *error;
    if(pcap_lookupnet(device, &net, &mask, error )==-1){
        fprintf(stderr,"Error looking up net: %s", error );
        exit(EXIT_FAILURE);
        }
}

