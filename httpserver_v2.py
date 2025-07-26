import socket
import signal
import sys
# import time
import multiprocessing
from scapy.all import sniff, TCP, IP
import os


class HTTPServer:
    def __init__(self, listen_ip, listen_port):
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_socket.bind((listen_ip, listen_port))

        self.packet_count = 0
        self.paths = []
        

        self.connections = [] # All accepted sockets
        

        pass

    # def start(self):
    #     pass

    def handleRequest(self):
        request_type, path, _ = 

    def validatePath(self, path):
        if self

    def handleHeaders():
        pass

    def handleBody():
        pass

    def close(self):
        self.listen_socket.close()

    # def __del__(self):
    #     '''
    #     Clean up sockets and files
    #     '''

    #     pass

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 8080
packet_count = 0

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
        
        request = client_socket.recv(1024).decode()
        print(request)
        headers = request.split('\n')
        first_header_components = headers[0].split()

        http_method = first_header_components[0]
        path = first_header_components[1]

        if http_method == 'GET':

            content = "Hello\r\n"
            print("Sending response: " + content)
            response = 'HTTP/1.1 200 OK\r\n\r\n' + content
        else:
            response = 'HTTP/1.1 405 Method Not Allowed\r\n\r\nAllow: GET'

        client_socket.sendall(response.encode())

        client_socket.close()