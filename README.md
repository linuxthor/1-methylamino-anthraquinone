1-methylamino-anthraquinone
===========================

NMAP port scan detecting LKM for Linux.

I wrote this tool about 3 years ago and used it for a while on my HTC Desire C phone (it was the version with Beats by Dre audio!) When loaded the Kernel module registers a handler using dev_add_pack() and listens for incoming TCP packets that have characteristics of the following types of scans:  

* -sS (SYN scan) 
* -sX (Xmas Tree) 
* -sN (Null scan)
* -sF (FIN scan) 
* OS Detection Probes (T2-T7)
* Generic connect() to ports 20,21,23,138

In the original Android PoC this would trigger a discrete alert by pulsing the vibration motor for a few milliseconds (perceptible when holding the handset but very difficult to hear over light background noise.) 

Linux version logs the details of anomalies detected to the kernel ring buffer (where they may be read with dmesg) /proc/paranoid is also created which may be read to determine how many of each scan type have been received. 

