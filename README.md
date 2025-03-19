# TCP-IP-Stack
Simple TCP/IP stack  

### Instructions:
1. Comple code with `make`  
2. Run `sudo ./tcpip_stack <source_ip> <destination_ip> <source_port> <destination_port>`
3. Observe packets with something like wireshark

### My example (My destination is a virtual machine with IP: 192.168.254.136):
1. Ran `make`
2. Ran `sudo ./tcpip_stack 10.110.225.227 192.168.254.136 54321 80`
   - This outputs the following:  
     ![alt text](https://github.com/AriT000/TCP-IP-Stack/blob/main/image2.png)
3. We observe the packet being sent with Wireshark
   - Wireshark packet:  
     ![alt test](https://github.com/AriT000/TCP-IP-Stack/blob/main/image1.png)
