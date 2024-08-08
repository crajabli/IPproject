all:  
	gcc mypcap.c p2.c -o p2

test:  
	@echo
	@echo -n "User Name: "
	@whoami
	@echo
	./p2 trafficMixed.pcap       > studentOutput5.txt
	./p2 trafficArpIcmp2.pcap    > studentOutput6.txt
	diff -s    output5.txt         studentOutput5.txt
	@echo
	diff -s    output6.txt         studentOutput6.txt
	@echo
   
clean:
	rm -f p2 *.txt
