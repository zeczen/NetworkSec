import ipaddress
import subprocess
import sys
from datetime import datetime
from random import randint
from struct import unpack
from threading import Thread
from time import sleep

from scapy.arch import get_if_addr
from scapy.config import conf
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sniff, sendp

# Global variables
hosts = []  # the list of the hosts
arp_packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP()


def random_ip(network):
    """
    Generate random host ip in [network]

    :param network: the network to generate the random host from
    :return: the random ip address
    :rtype: str
    """

    network = ipaddress.IPv4Network(network)
    network_int, = unpack("!I", network.network_address.packed)
    # make network address into an integer

    rand_bits = network.max_prefixlen - network.prefixlen
    # calculate the needed bits for the host part

    rand_host_int = randint(0, 2 ** rand_bits - 1)
    # generate random host part

    ip_address = ipaddress.IPv4Address(network_int + rand_host_int)
    # combine the parts

    return ip_address.exploded


def received_arp(packet):
    """
    Handle the arp replay,
    print the host and writing him to the file

    :param packet: the received arp replay packet
    """
    ip_address = packet[ARP].psrc
    mac_address = packet[ARP].hwsrc
    host = (ip_address, mac_address)

    if host in hosts:
        return  # we found him already
    # else

    hosts.append(host)


def listen_arp():
    """
    Listening to the arp replay packets
    """
    sniff(
        lfilter=lambda packet: ARP in packet and packet[ARP].op == 2,
        prn=received_arp,
    )


def send_arp(network):
    """
    Send all the arp requests

    :param network: object of type ipaddress.IPv4Network, the current network
    """
    for host in network.hosts():
        arp_packet[ARP].pdst = str(host)
        sendp(arp_packet, verbose=0)


def ip_scanning(network_specification):
    """
    Send ping (arp request) to every possible ip in the network,
    write the hosts to the [OUTPUT_FILE]

    :param network_specification: the network ip including the mask
    """

    network = ipaddress.IPv4Network(network_specification, False)
    arp_packet[ARP].psrc = random_ip(network)
    # we send packets with a random ip

    t = Thread(target=listen_arp)
    t.daemon = True  # stop the thread when program exits

    t.start()  # run the sniff before sending the pings

    send_arp(network)  # send the arp request while sniffing

    sleep(.5)
    # give time for all the last packet to arrive before killing the program

    sys.exit()  # stop sniffing


def get_network_specification():
    """
    Generate the network ip including the mask using the command line

    :return: [network ip]/[network mask]
    :rtype: str
    """

    ip = get_if_addr(conf.iface)  # the current host ip
    try:
        # for linux
        with subprocess.Popen('ifconfig', stdout=subprocess.PIPE) as proc:
            for _ in range(30):
                line = proc.stdout.readline()
                if ip.encode() in line:
                    mask = list(filter(lambda x: x != b'',
                                       line.rstrip().split(b'netmask')[1].split(b' '))
                                )[0].decode()
                    break
            proc.kill()

    except FileNotFoundError:
        # for windows
        with subprocess.Popen('ipconfig', stdout=subprocess.PIPE) as proc:
            for _ in range(30):
                line = proc.stdout.readline()
                if ip.encode() in line:
                    break
            mask = proc.stdout.readline().rstrip().split(b':')[-1].replace(b' ', b'').decode()
            proc.kill()

    network = str(ipaddress.IPv4Network(f'{ip}/{mask}', False))
    return network


def scan():
    try:
        specification = get_network_specification()
    except ipaddress.NetmaskValueError:
        print('You must to connect to the network first')
        return

    ip_scanning(specification)
    return hosts


if __name__ == "__main__":
    main()
