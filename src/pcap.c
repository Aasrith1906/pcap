#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>


#define BUFF_SIZE 1024

char *get_default();
pcap_t *get_handle(char *device);

int main(int argc, char *argv[]){
    if(argc<1){
        printf("not enough arguments \n");
    }
    char *device;
    device = argv[1];
    if(strcmp(device, "default")==0){
        device = get_default();
    }
    else{
        printf("Device: %s \n", device);
    }
    pcap_t *handle;
    handle = get_handle(device);
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

