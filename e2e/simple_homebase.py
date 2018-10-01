#!/usr/bin/env python3

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        with open('{}.json'.format(i), 'w') as f:
            f.write(self.rfile.read(int(self.headers['Content-Length'])).decode('utf-8'))
        self.rfile.close()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')


for i in range(int(sys.argv[1])):
    HTTPServer(('0.0.0.0', 1337), Handler).handle_request()
