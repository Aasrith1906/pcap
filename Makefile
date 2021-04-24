
run:
	gcc ./src/pcap.c -o ./build/pcap -w -lpcap
	./build/pcap default 