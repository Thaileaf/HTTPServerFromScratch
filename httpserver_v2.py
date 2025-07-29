import socket
import signal
import sys
# import time
import multiprocessing
from scapy.all import sniff, TCP, IP
import os
import re
import logging
from collections import deque
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
DEBUG = True

handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger = logging.getLogger('Web application')
logger.addHandler(handler)
if DEBUG:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.WARNING)

    


STATUSES = {
    200: "200 OK",
    404: "404 Not Found"
}


class HTTPServer:
    def __init__(self, listen_ip: str, listen_port: int, 
                 paths: dict[str, str], listen_queue=5):
        self.server_ip = listen_ip
        self.server_port = listen_port
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_socket.bind((listen_ip, listen_port))
        self.listen_socket.listen(listen_queue)

        self.packet_count = 0
        self.paths = paths
        

        self.connections = {} # All accepted sockets
        

        pass

    
    def serveForever(self):
        print(f"Starting server for {self.server_ip}:{self.server_port}")
        while True:
            client_socket, client_address = self.acceptConnection()
            print(f"Connection initiated from {client_address}")

            try:
                self.handleRequest(client_socket)
            except Exception as e:
                print("Whoops request failed", e)


    def acceptConnection(self) -> tuple[socket.socket, tuple[str, int]]:
        client_socket, client_address = self.listen_socket.accept()
        self.connections[client_socket] = client_address # Python sockets hashable?? Nice
        return client_socket, client_address
    
    def closeConnection(self, client_socket):
        print(f"Closing connection: {self.connections[client_socket]}")
        del self.connections[client_socket]
        client_socket.close()

    

    def handleRequest(self, client_socket):
        CLRF = b'\r\n\r\n' 
        raw_headers = bytearray() # Stores incoming request and header
        raw_body = bytearray() # Stores body

        buffer = deque(maxlen=4)

        # Receive loop
        while True: 
            incoming = client_socket.recv(50) 
            header_end = -1
            logger.debug("Incoming bytes: %s", incoming)

            # Check clrf for end of headers
            # header_end = incoming.find(CLRF) # TODO: Handle what happens if CLRF gets cut off! Implement sliding window
            for i, byte in enumerate(incoming):
                buffer.append(byte)

                def findCLRF(buffer):
                    CLRF = b'\r\n\r\n'
                    for i, byte in enumerate(buffer):
                        if byte != CLRF[i]:
                            return False
                    return True
                
                if findCLRF(buffer):
                    header_end = i
                    break

            if header_end != -1: 
                break
            else:
                raw_headers += incoming


        raw_headers.extend(incoming[:header_end + 1])
        raw_body.extend(incoming[header_end + 1:])
        logger.debug("Raw headers: %s", raw_headers)
        logger.debug("Raw body: %s", raw_body)

        # Decode Headers
        headers = raw_headers.decode().split('\r\n')
        logger.debug("Decoded headers: %s", headers)
        
        # Request line
        request_line_arr = headers[0].split(" ")
        if len(request_line_arr) != 3:
                raise Exception("Malformed HTTP request line")
        
        method, path, version = request_line_arr # Version not used yet...
        
        # Validations
        if not self.validatePath(path):
            self.handle_404(client_socket)
            return

        parsed_headers = self.parseReqHeaders(headers[1:])
      
        if method == "GET":
            self.handleGET(path, client_socket, parsed_headers)
            return
        elif method == "POST":
            self.handlePOST(path, parsed_headers)
            return

  
            

    def handleGET(self, path, client_socket, headers):
        headers = {
            "Test1": "Test",
            "Test2": "Test"
        }
        response = self.craftResponse(200, headers, "What's up")

        logger.debug("GET Response is: %s", response)

        client_socket.sendall(response)
        self.closeConnection(client_socket)



    def handlePOST(self, path, headers):
        pass

    def handle_404(self, client_socket):
        response = self.craftResponse(404, {}, "404 resources not found")
        client_socket.sendall(response)
        self.closeConnection(client_socket)

    def craftResponse(self, code: int, headers: dict[str,str], content):
        '''
        Craft responses for requests. Does not need to pass in content length header, calcs by default
        '''
        # sending_headers = ...
        content_bytes = content.encode('utf-8')
        headers["Content-Length"] = str(len(content_bytes))
        header_lines = []
        for key, value in headers.items():
            header_lines.append(f"{key}: {value}")
        header_str = "\r\n".join(header_lines)
            
        response = (f'HTTP/1.1 {STATUSES[code]}\r\n{header_str}\r\n\r\n').encode('utf-8') + content_bytes
        logger.debug("Crafting response: %s", response)
        return response
        
    

    def validatePath(self, path) -> bool:
        if path not in self.paths:
            logger.debug("Cannot find path %s", path)
            return False
        return True

    def parseReqHeaders(self, headers) -> dict[str, str]:
        '''
        Parses a list of header strings into a dictionary
        '''
        parsed_headers = {}
        for header in headers:
            if not header: continue
            split_header = header.split(": ") 
            if len(split_header) != 2:
                raise Exception("Malformed header:", header)
            
            parsed_headers[split_header[0]] = split_header[1]

        return parsed_headers

    def receiveBody():
        pass

    def close(self):
        print("Closing server...")
        self.listen_socket.close()

    # def __del__(self):
    #     '''
    #     Clean up sockets and files
    #     '''

    #     pass

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 8080
# packet_count = 0

def run_server():
  
    server = HTTPServer(SERVER_HOST, SERVER_PORT,paths={"/":"True:)"})
    def signal_handler(sig, frame):
        print('You pressed Ctrl+C!')
        server.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    server.serveForever()





run_server()