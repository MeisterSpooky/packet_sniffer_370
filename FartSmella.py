import socket
import struct
import textwrap

def unpackEF(ef):
    destination_MAC, source_MAC, protocol = struct.unpack("!6s 6s H", ef[:14])
    return formatMAC(destination_MAC), formatMAC(source_MAC), socket.htons(protocol), ef[14:]

def formatMAC(MAC):
    formatted_MAC = map("{:02X}", MAC)
    return ':'.join(formatted_MAC)

if __name__ == "__main__":
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        ethernet_frame, address = connection.recvfrom(65536)

        destination_MAC, source_MAC, protocol, data = unpackEF(ethernet_frame)

        print("Ethernet Frame:")
        print(f"Destination: {destination_MAC}\nSource: {source_MAC}\nProtocol: {protocol}\n")