#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#ifndef _STANDARD_H
#define _STANDARD_H


#define BUFF_SIZE 1024

char *get_default();
pcap_t *get_handle(char *device);
void get_device_details(char *device, bpf_u_int32 net, bpf_u_int32 mask);

#endif 