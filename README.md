1-methylamino-anthraquinone
===========================

Port scan detecting LKM for Android on the HTC Desire C (and possibly others) or Linux. 

Primarily developed as a proof of concept tool for the HTC Desire C Android phone. Once loaded the Kernel module registers a handler using the dev_add_pack() method and listens for incoming packets that are sent to a handful of well known ports (21, 22, 80, 443) or that have features that are characteristic of the NMAP OS detection probes (T2-T7) will trigger a discrete alert by pulsing the vibration motor for a few milliseconds, this is perceptible when holding the handset but extremely difficult to hear over light background noise. 

Linux version is provided that simply prints the alerts to the Kernel ring buffer. 

Building Android version requires Kernel sources from HTC and Android SDK/NDK.

TODO: Add NMAP UDP & ICMP probe detection. Improve TCP ECN detection. /proc device on Linux. Send fake responses to confuse NMAP OS detection. 
