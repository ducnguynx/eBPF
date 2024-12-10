# eBP for counting Ethernet packets
This program will counts how many packets that a specific IP Adress received and transmisted 
## Notes
You will need eBPF installed for running this program  
Your machine does not need [CO-RE](https://docs.ebpf.io/concepts/core/) eBPF support
For further details on how to install dependencies, please see:  
[BCC](https://github.com/iovisor/bcc/blob/master/INSTALL.md)  
[libbpf](https://github.com/libbpf/libbpf)  
[bpftool](https://github.com/libbpf/bpftool)  
## Install
clone this repo  
```
git clone https://github.com/ducnguynx/eBPF_ETH.git
cd eBPF_ETH
```
install  
```
sudo make
```
change the name of the interface (for mine wlan0) to that fit yours in start.sh and stop.sh  
running the program  
```
sudo ./start.sh
# in a new terminal
sudo ./hello_usr
```
stop the program
```
sudo ./stop.sh
```
## License
This work is dual-licensed under BSD 2-clause license and GNU LGPL v2.1 license.
You can choose between one of them if you use this work.
`SPDX-License-Identifier: BSD-2-Clause OR LGPL-2.1`
