import socket
import signal
import sys
# import time
import multiprocessing
from scapy.all import sniff, TCP, IP
import os

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 8080
packet_count = 0


# Cons of current version:
    # Doesn't handle if request is not all contained in recv
        # Will break if packets are delayed on real network. Works on local network tho
        # Loses data on larger headers
    # Not concurrent

def run_server():
    print(f"[Server Process, PID: {multiprocessing.current_process().pid}] Starting up...")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((SERVER_HOST, SERVER_PORT))

    server_socket.listen(5)

    print(f'Listening on port {SERVER_PORT} ...') # if all goes well, we will print that we have started listening on a specific port

    # Clean up socket
    def signal_handler(sig, frame):
        print('You pressed Ctrl+C!')
        server_socket.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)



    while True: 
        
        client_socket, client_address = server_socket.accept()
        
        request = client_socket.recv(1024).decode() # Simple mechanism, needs polling for real requests over the network
        print(request)
        headers = request.split('\n')
        first_header_components = headers[0].split()

        http_method = first_header_components[0]
        path = first_header_components[1]

        if http_method == 'GET':

            content = "Hello"

            headers = f"Content-Length: {len(content)}"
            print("Sending response: " + content)
            response = f'HTTP/1.1 200 OK\r\n{headers}\r\n\r\n' + content
        else:
            response = 'HTTP/1.1 405 Method Not Allowed\r\nAllow: GET'

        client_socket.sendall(response.encode())

        client_socket.close()



def packet_handler(packet):
    """
    When packet is found
    """
    global packet_count
    packet_count += 1    
    
    # Get the TCP layer to see payload size
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        ip_layer = packet[IP]
        source, dest = ip_layer.src, ip_layer.dst


        direction = ""
        if tcp_layer.dport == SERVER_PORT:
            direction = "REQUEST"
        elif tcp_layer.sport == SERVER_PORT:
            direction = "RESPONSE"

        payload_size = len(tcp_layer.payload)
        if payload_size > 0:
            print(f"{direction} Packet #{packet_count}: Seq={packet[TCP].seq}, {source}:{tcp_layer.sport} -> {dest}:{tcp_layer.dport}, Payload Size={payload_size} bytes")
    else:
        print(f"Packet #{packet_count}: {packet.summary()}")

def packet_counter():
    print(f"[Sniffer Process, PID: {multiprocessing.current_process().pid}] Starting up...")

    bpf_filter = f"tcp and (src port {SERVER_PORT} or dst port {SERVER_PORT})"
    sniff(iface="lo", filter=bpf_filter, prn=packet_handler, store=0)


# if __name__ == "__main__":
print(f"Main process {os.getpid()} starting")
server_process = multiprocessing.Process(target=run_server)
packet_process = multiprocessing.Process(target=packet_counter)

# Start both processes
server_process.start()
packet_process.start()

