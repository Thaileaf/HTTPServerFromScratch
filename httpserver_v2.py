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

import logging

LONG_LOGS = False
DEBUG = True


class CustomFormatter(logging.Formatter):
    """Custom formatter to add colors to logging output."""

    # Define ANSI escape codes for colors
    grey = "\x1b[38;20m"
    green = "\x1b[32;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"

    # Define the format string
    format_str = "%(asctime)s - %(name)s - %(levelname)-8s - " + reset + "%(message)s"

    # Map log levels to format strings with colors
    FORMATS = {
        logging.DEBUG: green + format_str + reset,
        logging.INFO: green + format_str + reset,
        logging.WARNING: yellow + format_str + reset,
        logging.ERROR: red + format_str + reset,
        logging.CRITICAL: bold_red + format_str + reset
    }
    
    max_len = 500

    def format(self, record):


        record_copy = logging.makeLogRecord(record.__dict__)

        log_fmt = self.FORMATS.get(record_copy.levelno)
        formatter = logging.Formatter(log_fmt)
        formatted =  formatter.format(record_copy)
        if len(formatted) > self.max_len:
            return formatted[:self.max_len] + f"...({len(formatted) - self.max_len} more chars)\n"
        return formatted


handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(CustomFormatter())

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
    """A simple HTTP server that serves static content"""

    def __init__(self, listen_ip: str, listen_port: int, 
                 routes: dict[str, str], listen_queue=5):
        
        self.server_ip = listen_ip
        self.server_port = listen_port
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_socket.bind((listen_ip, listen_port))
        self.listen_socket.listen(listen_queue)

        self.packet_count = 0
        self.routes = routes
        

        self.connections = {} # All accepted sockets


    
    def serve_forever(self):
        """ Core running loop, handles incoming connections and passes to request handler """

        print(f"Starting server for {self.server_ip}:{self.server_port}")
        while True:
            client_socket, client_address = self.accept_connection()
            print(f"Connection initiated from {client_address}")

            try:
                self.handle_request(client_socket)
            except Exception:
                logger.exception(f"Whoops an error occurred with {client_address}")
            finally:
                if client_socket in self.connections:
                    self.close_connection(client_socket)


    def accept_connection(self) -> tuple[socket.socket, tuple[str, int]]:
        """ Accepts a socket connection, adds it to own socket list """

        client_socket, client_address = self.listen_socket.accept()
        self.connections[client_socket] = client_address # Python sockets hashable?? Nice
        return client_socket, client_address
    
    def close_connection(self, client_socket):
        """ Closes a connection, cleans up from own socket list """

        print(f"Closing connection: {self.connections[client_socket]}")
        try:
            client_socket.close()
            del self.connections[client_socket]
        except:
            logger.exception("Could not close socket and clean up properly")


    

    def handle_request(self, client_socket):
        """ Handles a request from a single socket """
        if not client_socket:
            logger.exception("Client socket does not exist?")

        CLRF = b'\r\n\r\n'
        raw_headers = bytearray() # Stores incoming request and header
        raw_body = bytearray() # Stores body

        buffer = deque(maxlen=4)

        # Receive loop
        while True:
            incoming = client_socket.recv(50) # TODO: Handle what happens if connection is open but no data is sent. Close connection...
            if not incoming: break # Closes if tcp socket does not send anything
            header_end = -1
            logger.debug("Incoming bytes: %s", incoming)

            # Check clrf for end of headers
            # header_end = incoming.find(CLRF) # TODO: Handle what happens if CLRF gets cut off! Implement sliding window

            # Here is the sliding window implementation. Just a simple circular queue
            for i, byte in enumerate(incoming):
                buffer.append(byte)

                def find_CLRF(buffer):
                    """ Compares bytes to find CLRF from buffer """
                    CLRF = b'\r\n\r\n'
                    for i, byte in enumerate(buffer):
                        if byte != CLRF[i]:
                            return False
                    return True
                
                if find_CLRF(buffer):
                    header_end = i
                    break

            if header_end != -1:
                break
            else:
                raw_headers += incoming

        
        raw_headers.extend(incoming[:header_end + 1])
        raw_body.extend(incoming[header_end + 1:])
        logger.debug("Raw request headers: %s", raw_headers)
        logger.debug("Raw request body: %s", raw_body)

        # Decode Headers
        headers = raw_headers.decode().split('\r\n')
        logger.debug("Decoded headers: %s", headers)
        
        # Request line
        request_line_arr = headers[0].split(" ")
        if len(request_line_arr) != 3:
                raise Exception("Malformed HTTP request line")
        
        method, route, version = request_line_arr # TODO: Version not used yet...
        
        # Validations
        if not self.validate_path(route):
            self.handle_404(client_socket)
            return

        parsed_headers = self.parse_req_headers(headers[1:])
      
        if method == "GET":
            self.handle_get(route, client_socket, parsed_headers)
        elif method == "HEAD":
            self.handle_head(route, client_socket, parsed_headers)
        elif method == "POST":
            self.handle_post(route, parsed_headers)
        
        self.close_connection(client_socket) # Currently have to close each connection because no concurrency.


    
    def read_file(self, route):
        """ Finds the corresponding path on the OS and returns file data encoded 
        TODO: Could potentially optimize it future with a read semaphore and file descriptor
        to avoid reopening files

        Args:
            route (str): URL route

        Returns:
            data (str): Read file from disk in bytes
            headers (dict[str, str]): Additional headers from files
        """
        # Translate route to path and read file as bytes
        path = "public/" + self.routes[route]
        logger.debug("File path is %s", path)
        logger.debug("Path being read: %s", path)
        with open(path, 'rb') as file: # TODO: Need to optimize so that we send small chunks of data at a time, instead of whole file at once
            data = file.read()

        # Determine any headers related to file
        file_headers = {
            # Enter default headers here
        }
        _, ext = os.path.splitext(path)
        logger.debug("File ext is %s", ext)
        file_headers['Content-Type'] = self.get_media_type(ext)

        return data, file_headers
    
    def get_media_type(self, extension):
        """
        Returns the MIME type for a given file extension.
        Uses a dictionary for efficient lookup and provides a default for unknown types.
        """
        # A dictionary mapping common file extensions to their MIME types
        media_types = {
            # Images 
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gif",
            ".svg": "image/svg+xml",
            ".ico": "image/vnd.microsoft.icon",

            # Audio and Video 
            ".mp3": "audio/mpeg",
            ".wav": "audio/wav",
            ".ogg": "audio/ogg",
            ".mp4": "video/mp4",
            ".webm": "video/webm",
            ".mov": "video/quicktime",
            ".ts": "video/mp2t", # HLS Segment

            # Text and Documents 
            ".html": "text/html",
            ".htm": "text/html",
            ".css": "text/css",
            ".txt": "text/plain",
            ".pdf": "application/pdf",

            # Scripts and Data 
            ".js": "application/javascript",
            ".json": "application/json",
            ".xml": "application/xml",
            ".m3u8": "application/vnd.apple.mpegurl", # HLS Manifest
            ".mpd": "application/dash+xml", # DASH Manifest
            
            # Archives 
            ".zip": "application/zip",
            ".tar": "application/x-tar",
        }
        
        # Returns media type, octet stream if extension not found
        return media_types.get(extension.lower(), "application/octet-stream")

    def handle_get(self, route, client_socket, request_headers):
        """ Sends back response to socket for GET requests """
        response_headers = {
            "Thaileaf": "was here",
        }

        file_data, file_headers = self.read_file(route)
        response_headers.update(file_headers)
        response = self.craft_response(200, response_headers, file_data)

        logger.debug("GET Response is: %s", response)

        client_socket.sendall(response)

    def handle_head(self, path, client_socket, request_headers):
        """ Sends response bytes back to socket for HEAD requests """
        response_headers = {
            "Thaileaf": "was here",
        }

        _, file_headers = self.read_file(path) # TODO only way to read the meta data is to read whole file. Fix future
        response_headers.update(file_headers)
        response = self.craft_response(200, response_headers)
        logger.debug("HEAD Response is: %s", response)

        client_socket.sendall(response)


    def handle_post(self, path, headers):
        # Maybe I'll make it handle post in the future with proxying, for now I'll just put a 405 method not allowed
        pass

    # def handle

    def handle_404(self, client_socket):
        """ Handles when a 404 occurs"""
        response = self.craft_response(404, {}, "404 resources not found")
        client_socket.sendall(response)

    def craft_response(self, code: int, headers: dict[str,str], data=b''):
        """ Craft responses for requests. Does not need to pass in content length header, calcs by default """
        # content_bytes = content.encode('utf-8')
        # data
        if data:
            headers["Content-Length"] = str(len(data))
        header_lines = []
        for key, value in headers.items():
            header_lines.append(f"{key}: {value}")
        header_str = "\r\n".join(header_lines)
            
        response = (f'HTTP/1.1 {STATUSES[code]}\r\n{header_str}\r\n\r\n').encode('utf-8') + data
        logger.debug("Crafting response: %s", response)
        return response
        
    

    def validate_path(self, path) -> bool:
        if path not in self.routes:
            logger.debug("Cannot find path %s", path)
            return False
        return True

    def parse_req_headers(self, headers) -> dict[str, str]:
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

    def receive_body():
        pass

    def close(self):
        print("Closing server...")
        self.listen_socket.close()



SERVER_HOST = '0.0.0.0'
SERVER_PORT = 8080
# packet_count = 0

def run_server():
  
    open_routes = {
        "/":"index.html", 
        "/image.png": "image.png",
        "/video.mp4": "video.mp4"
        }
    server = HTTPServer(SERVER_HOST, SERVER_PORT,routes=open_routes)
    def signal_handler(sig, frame):
        print('You pressed Ctrl+C!')
        server.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    server.serve_forever()





run_server()