# ARP Spoofer
A Python Program that does ARP Spoofing on the given targets, implementing a Man-in-the-Middle Attack.<br />
During the runtime of this program, each packet that is sent/recieved by the Target goes through our Device.

## Requirements
Languange Used = Python3<br />
Modules/Packages Used:
* re
* os
* datetime
* optparse
* subprocess
* threading
* time
* colorama
* scapy

## Input
The arp_spoofer.py takes the following arguments through the command that is used to run the Python Program:
* '-g', "--gateway" : IP Address of Gateway of the Network
* '-t', "--target" : IP Address of Target/Targets to Spoof (seperated by ',')
* '-i', "--interface" : Delay between sending ARP Packets to the Targets (Default = 5 seconds)
* '-d', "--delay" : Delay between sending ARP Packets to the Targets (Default = 5 seconds)
* '-l', "--load" : Load Targets from a file

## Working of ARP Spoofing Attack
In a Network, devices identify and communitcate with each other using their MAC Addresses (Media Access Control Address). They get to know about the IP Address and MAC Address of the other devices connected to the same network using ARP (Address Resolution Protocol)<br />
The vulnerability of ARP that is exploited here is that there is no verfication process to check if the ARP Response Packet recieved by a device came from the device that is mentioned as 'source' in the packet.<br /><br />

## Working
After getting all the required arguments, the program starts spoofing the targets.<br />
It first enables IPv4 Routing, so that the traffic through our device can flow. It does that by writing '1' to file '/proc/sys/net/ipv4/ip_forward'.<br />
It then creates threads for each target to spoof simultaneously.<br />
In each thread, it first creates an ARP response with our Device's MAC Address as the source MAC and Gateway's IP as the source IP and sends it to the target. As in ARP, there is no verification process regarding that the packet is sent by the device that is mentioned in the source of the packet, so the target stores that our MAC Address is the MAC Address of the Gateway. And similar is done for the Gateway.<br />
The Programs sends the ARP Response Packets to the Targets and Gateway in regular intervals. That is the delay provided by the user.<br />
The delay should be about 5 seconds, because if the delay is small it would flood the network with the ARP Response Packets or if the delay is too long the ARP Spoofing may not work as default MAC Addresses may get restored.<br />
On closing the Program with CTRL+C (KeyboardInterrupt), it first disables IPv4 Routing by writing '0' to '/proc/sys/net/ipv4/ip_forward'. And then sending the ARP Responsed to Targets and Gateway with the original MAC Addressed to restore the normal working of the network.<br /><br />

### Note
We can hide our identity by changing our Device's MAC Address.<br />
See https://github.com/Gill-Singh-A/MAC-Address-Changer.git for more information.