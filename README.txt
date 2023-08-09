Amanda Yun, akyun@ucsc.edu, akyun, 1903241

Files Submitted:
finalcontroller.py
This is the skeleton code that forwards the correct packets to the corresponding hosts. Within this code, there are a bunch of conditional statements that test where the packet needs to go. ARP packets are flooded immediately but IP packets must be looked at carefully. We build a firewall to let some packets flow through some switches and some to be dropped. 
final_skel.py
This is the skeleton code for the topology of our hosts and switches. It gives each host a unique ip address and it creates all the needed switches. These switches and hosts are connected through specified ports. Only one link per port!