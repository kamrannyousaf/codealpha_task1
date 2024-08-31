import socket
import struct
import textwrap

def create_socket():
    # Create a raw socket to capture all network traffic
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    return conn

def get_mac_addr(bytes_addr):
    # Convert a MAC address to a human-readable format
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def ethernet_frame(data):
    # Unpack the Ethernet frame
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def main():
    conn = create_socket()

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

        # Additional processing can be added here for IP, TCP, etc.

if __name__ == "__main__":
    main()
