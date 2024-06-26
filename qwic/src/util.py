#!/usr/bin/python3

from typing import Tuple
import sys
import os
import math
import datetime
from scapy.all import *


GLOBAL_MONITOR_FILE = None
GLOBAL_DATA_FILE = None


class ParsingException(Exception):
    pass


def initialize_outputs(monitor_file_pos, data_file_pos):
    global GLOBAL_MONITOR_FILE, GLOBAL_DATA_FILE

    if GLOBAL_MONITOR_FILE is not None:
        raise Exception("Monitor file already initialized")

    if GLOBAL_DATA_FILE is not None:
        raise Exception("Data file already initialized")

    # Monitor file
    if monitor_file_pos is not None:
        try:
            monitor_file = open(monitor_file_pos, 'a')
            os.chown(monitor_file_pos, 1001, 1001)
            os.chmod(monitor_file_pos, 0o400)
        except Exception as e:
            print(f"Could not open monitor file {monitor_file_pos}: {e}")
            exit(1)

        GLOBAL_MONITOR_FILE = monitor_file
    else:
        monitor_file = sys.stdout
        GLOBAL_MONITOR_FILE = monitor_file

    # Data file
    if data_file_pos is not None:
        try:
            data_file = open(data_file_pos, 'a')
            os.chown(data_file_pos, 1001, 1001)
            os.chmod(data_file_pos, 0o400)
        except Exception as e:
            print(f"Could not open data file {data_file_pos}: {e}")
            exit(1)

        GLOBAL_DATA_FILE = data_file
    else:
        data_file = sys.stdout
        GLOBAL_DATA_FILE = data_file

    return monitor_file, data_file


def print_monitor(*args, **kwargs):
    global GLOBAL_MONITOR_FILE

    header = f"[{datetime.datetime.utcnow().isoformat()}] (MONITOR) - "

    if GLOBAL_MONITOR_FILE is not None and GLOBAL_MONITOR_FILE != sys.stdout:
        print(header, file=GLOBAL_MONITOR_FILE, end="")
        print(*args, file=GLOBAL_MONITOR_FILE, **kwargs)
        GLOBAL_MONITOR_FILE.flush()
    else:
        raise Exception("Monitor file not initialized!")

    print(header, end="")
    print(*args, **kwargs)


def print_data(*args, **kwargs):
    global GLOBAL_DATA_FILE

    header = f"[{datetime.datetime.utcnow().isoformat()}] (DATA) - "

    if GLOBAL_DATA_FILE is not None and GLOBAL_DATA_FILE != sys.stdout:
        print(header, file=GLOBAL_DATA_FILE, end="")
        print(*args, file=GLOBAL_DATA_FILE, **kwargs)
        GLOBAL_DATA_FILE.flush()
    else:
        raise Exception("Data file not initialized!")

    print(header, end="")
    print(*args, **kwargs)


def print_ipv4(addr: int) -> str:
    '''
    Function to print in readable way an ipv4 address
    '''
    return "%d.%d.%d.%d" % (addr & 0xff,
                            (addr >> 8) & 0xff,
                            (addr >> 16) & 0xff,
                            (addr >> 24) & 0xff)


def print_byte(byte: int) -> str:
    return bin(byte)[2:].zfill(8)

def get_varint(packet_bytes: bytes, offset: int) -> Tuple[int, int]:
  """Parses a variable-length integer (varint) from a QUIC packet using Scapy.

  Args:
      packet_bytes: The raw bytes of the QUIC packet.
      offset: The starting offset within the packet data.

  Returns:
      A tuple containing the parsed integer value and the updated offset,
      or raises an exception for invalid varints.
  """

  # Extract first byte and isolate continuation bits
  if offset >= len(packet_bytes):
    raise IndexError("Insufficient bytes for varint")
  v = packet_bytes[offset]
  offset += 1
  prefix = v >> 6
  length = 1 << prefix

  # Check for valid length
  if length > 8:
    raise ValueError("Invalid varint length")

  result = v & 0x3f

  # Iterate through subsequent bytes (based on length)
  for _ in range(1, length):
    if offset >= len(packet_bytes):
      raise IndexError("Insufficient bytes for varint")
    next_byte = packet_bytes[offset]
    offset += 1
    result = (result << 8) | next_byte  # Combine with next byte

  return result, offset


# def get_varint(packet_bytes: bytes, offset: int) -> Tuple[int, int]:
#   """Parses a variable-length integer (varint) from a QUIC packet using Scapy.

#   Args:
#       packet_bytes: The raw bytes of the QUIC packet.
#       offset: The starting offset within the packet data.

#   Returns:
#       A tuple containing the parsed integer value and the updated offset.
#   """
#   v = packet_bytes[offset]
#   offset += 1

#   prefix = v >> 6  # Extract prefix bits
#   length = 1 << prefix  # Calculate length based on prefix
#   result = v & 0x3f  # Isolate continuation bits

#   for _ in range(1, length):
#     next_byte = packet_bytes[offset]
#     offset += 1
#     result = (result << 8) | next_byte  # Combine with next byte

#   return result, offset

# def get_varint(packet_bytearray: bytearray, offset: int) -> Tuple[int, int]:
#     v = packet_bytearray[offset]
#     offset += 1

#     prefix = v >> 6
#     length = 1 << prefix
#     v = v & 0x3f

#     for _ in range(1, length):
#         v = (v << 8) + packet_bytearray[offset]
#         offset += 1

#     return v, offset
