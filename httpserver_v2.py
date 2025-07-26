import socket
import signal
import sys
# import time
import multiprocessing
from scapy.all import sniff, TCP, IP
import os
import re

# class Headers:
#     def __init__(self):
#         # Headers that can be used in both requests and responses.
#         self.general_headers = {
#             "Cache-Control": None,
#             "Connection": None,
#             "Date": None,
#             "Pragma": None,
#             "Transfer-Encoding": None,
#             "Upgrade": None,
#             "Via": None,
#         }

#         # Headers that are specific to client requests.
#         self.request_headers = {
#             "Accept": None,
#             "Accept-Charset": None,
#             "Accept-Encoding": None,
#             "Accept-Language": None,
#             "Authorization": None,
#             "Cookie": None,
#             "Expect": None,
#             "From": None,
#             "Host": None,
#             "If-Match": None,
#             "If-Modified-Since": None,
#             "If-None-Match": None,
#             "If-Range": None,
#             "If-Unmodified-Since": None,
#             "Range": None,
#             "Referer": None,
#             "User-Agent": None,
#         }

#         # Headers that are specific to server responses.
#         self.response_headers = {
#             "ETag": None,
#             "Location": None,
#             "Proxy-Authenticate": None,
#             "Retry-After": None,
#             "Server": None,
#             "Set-Cookie": None,
#             "Vary": None,
#             "WWW-Authenticate": None,
#         }

#         # Headers describing the payload body (Representation Headers).
#         self.entity_headers = {
#             "Content-Encoding": None,
#             "Content-Language": None,
#             "Content-Length": None,
#             "Content-Location": None,
#             "Content-MD5": None,
#             "Content-Range": None,
#             "Content-Type": None,
#             "Expires": None,
#             "Last-Modified": None,
#         }
        
#         # Common non-standard, security, or other notable headers.
#         self.additional_headers = {
#             "Content-Security-Policy": None,
#             "DNT": None,
#             "Origin": None,
#             "Strict-Transport-Security": None,
#             "X-Forwarded-For": None,
#             "X-Frame-Options": None,
#             "X-Requested-With": None,
#         }

# # class Headers

class HTTPServer:
    def __init__(self, listen_ip, listen_port, listen_queue):
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_socket.bind((listen_ip, listen_port))
        self.listen_socket.listen(listen_queue)

        self.packet_count = 0
        self.paths = {}
        

        self.connections = [] # All accepted sockets
        

        pass

    # def start(self):
    #     pass
    def serveForever(self):
        while True:
            client_socket, client_address = self.listen_socket.accept()


            try:
                self.handleRequest(client_socket)
            except Exception as e:
                print("Whoops request failed")

                    

    def handleRequest(self, client_socket):
        CLRF = b'\r\n\r\n' 
        raw_headers = bytearray() # Stores incoming request and header
        raw_body = bytearray() # Stores body
        # Receive loop
        while True: 
            incoming = client_socket.recv(4096)
            
            # Check clrf for end of headers
            header_end = incoming.find(CLRF)
            if header_end != -1: 
                break
            else:
                raw_headers.append(incoming)

        # Split data appropriately between body headers
        split_incoming = incoming.split(CLRF, 1)

        raw_headers.append(split_incoming[0])
        raw_body.append(split_incoming[1])

        # Decode Headers
        headers = raw_headers.decode().split('\n')
        
        # Request line
        request_line_arr = headers[0].split(" ")
        if len(request_line_arr) != 3:
                raise Exception("Malformed HTTP request line")
        method, path, version = request_line_arr
        

        self.validatePath(path)
        
        parsed_headers = self.parseReqHeaders(headers[1:])

        if method == "GET":
            self.handleGET(path, parsed_headers)

        elif method == "POST":
            self.handlePOST(path, parsed_headers)

    def handleGET(self, path, headers):
        pass

    def handlePOST(self, path, headers):
        pass

    def craftResponse(self, code, headers: dict[str,str], content):
        
        for headers
        headers = f"Content-Length: {len(content)}\r\n"
        print("Sending response: " + content)
        response = f'HTTP/1.1 200 OK\r\n{headers}\r\n' + content
        
    

    def validatePath(self, path):
        if path not in self.paths:
            raise Exception("Path Not Found")

    def parseReqHeaders(self, headers):
        parsed_headers = {}
        for header in headers:
            split_header = header.split(": ") 
            if len(split_header) != 2:
                raise Exception("Malformed header")
            
            parsed_headers[split_header[0]] = split_header[1]

        return parsed_headers

    def receiveBody():
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