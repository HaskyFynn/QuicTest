from typing import Tuple
from hparser import parse_long_header 
from hparser import parse_short_header
from hparser import parse_first_layers
from scapy.all import *
from scapy.all import Packet, sniff
from scapy.layers.inet import UDP


# Provided functions for parsing QUIC headers
def hparse_quic_packet(packet_bytearray: bytearray) -> None:
    # Parse initial layers (IP, UDP)
    layers_info, payload_offset = parse_first_layers(packet_bytearray)
    
    # Check if UDP port matches QUIC (optional)
    #if layers_info["port_dst"] != 6121 :  # QUIC typically uses port 443
        #print(f"Skipping packet: Non-standard UDP port ({layers_info['port_dst']})")
        #return

    # Parse QUIC header (short or long)
    first_byte = packet_bytearray[payload_offset]
    if first_byte & 0x80:  # Check for Long Header format
        parsed_header, _ = parse_long_header(first_byte, packet_bytearray, payload_offset)
    else:
        parsed_header, _ = parse_short_header(first_byte, packet_bytearray, payload_offset)

    # Extract connection IDs and type (handle potential KeyError)
    try:
        packet_type = parsed_header["packet_type"]
        if packet_type != "1RTT" :
         version = parsed_header.get("version")
         src_conn_id_int = parsed_header["src_conn_id_int"]
         src_conn_id_hex = parsed_header["src_conn_id"]
         dest_conn_id_int = parsed_header["dest_conn_id_int"]
         dest_conn_id_hex = parsed_header["dest_conn_id"]
        
         # Print information (use the retrieved values or placeholders)
         print(f"Source Connection ID (int): {src_conn_id_int}")
         print(f"Source Connection ID (hex): {src_conn_id_hex}")
         print(f"Destination Connection ID (int): {dest_conn_id_int}")
         print(f"Destination Connection ID (hex): {dest_conn_id_hex}")
         print(f"Packet Type: {packet_type}")
         print(f"Version: {version}") 
         
         
         
         print("-" * 20)  # Optional separator between packets
         
        else:
         spin_bit = parsed_header.get("spin_bit")
         packet_number_length = parsed_header["packet_number_length"]
         packet_number = parsed_header["packet_number"]
            
         print(f"Spin Bit: {spin_bit}")
         print(f"Packet Number Length: {packet_number_length}")
         print(f"Packet Number: {packet_number}")
         print(f"Packet Type: {packet_type}")
            
         print("-" * 20)  # Optional separator between packets


    except KeyError as e:
        print(f"Error parsing header: {e}")
        version, packet_type, src_conn_id_int, src_conn_id_hex, dest_conn_id_int, dest_conn_id_hex, spin_bit, packet_number_length, packet_number = None, None, None, None, None, None, None, None, None       

from fparser import parse_frames, parse_frames_rec, generate_result



def fparse_quic_packet(packet_bytearray: bytearray) -> None:
    # Parse initial layers (IP, UDP)
    layers_info, payload_offset = parse_first_layers(packet_bytearray)

    # Parse QUIC frames
    frames, parse_result = parse_frames(packet_bytearray[payload_offset:], payload_offset)

    # Handle parsing results
    if parse_result["status"] != 200:
        print(f"Error parsing frames: {parse_result['reason']}")
    else:
        # Process parsed frames
        for frame in frames:
            frame_name = frame["frame_name"]
            # Print frame details based on type
            if frame_name == "STREAM":
                print(f"\n  Stream Frame:")
                print(f"    Stream ID: {frame['stream_id']}")
                print(f"    Stream Type: {frame['stream_type']}")
                print(f"    Data Offset: {frame['offset']}")
                print(f"    FIN Flag: {frame['fin']}")
                print(f"    Data Length: {frame['len']}")
            elif frame_name == "ACK":
                print(f"\n  ACK Frame:")
                print(f"    Largest Acknowledged: {frame.get('largest_ack')}")
                print(f"    Acknowledged Blocks: {frame.get('acked')}")
            elif frame_name == "CONNECTION_CLOSE" or frame_name == "APPLICATION_CLOSE":
                print(f"\n  {frame_name} Frame:")
                print(f"    Error Code: {frame.get('error_code')}")
                print(f"    Reason Phrase: {frame.get('reason_phrase')}")
            elif frame_name == "PADDING":
                print(f"\n  Padding Frame:")
                print(f"    Amount of padding: {frame.get('amount')}")
            elif frame_name in ("STREAM_DATA_BLOCKED", "STREAMS_BLOCKED_BIDI", "STREAMS_BLOCKED_UNI"):
                print(f"\n  Stream Blocked Frame:")
                print(f"    Stream ID (if applicable): {frame.get('stream_id')}")
                print(f"    Limit: {frame.get('limit')}")
            elif frame_name in ("NEW_CONNECTION_ID", "RETIRE_CONNECTION_ID"):
                print(f"\n  Connection ID Frame:")
                print(f"    Sequence Number: {frame.get('sequence_number')}")
                if frame_name == "NEW_CONNECTION_ID":
                    print(f"      Connection ID: {frame.get('connection_id')}")
                    print(f"      Stateless Reset Token: {frame.get('stateless_reset_token')}")
            else:
                print(f"\n  Unknown Frame ({frame_name})")
            print("-" * 20)  # Optional separator between frames



# Open the PCAP file
with open('quic_traffic.pcap', 'rb') as f:
    pcap_data = f.read()

# Loop through packets in the PCAP data
for packet in rdpcap("quic_traffic.pcap")[7]:
    hparse_quic_packet(bytes(packet))
    fparse_quic_packet(bytes(packet))
    



   