import http.server
import ssl
from http.server import HTTPServer
import logging
from datetime import datetime
import argparse

parser = argparse.ArgumentParser(prog='redirect')
parser.add_argument('-url', type=str, default='', help='Location to redirect to.')
parser.add_argument('-respond', type=str, default='', help='Body text to respond.')
parser.add_argument('-p', type=int, default=8080, help='Port to serve [Default=8080]')
parser.add_argument('-c', type=int, default=200, help='HTTP code to return [Default=200]')
parser.add_argument('-ssl', action='store_true', help='Run SSL ("local.key", "local.crt")')
parser.add_argument('-log', type=str, default='', help='Logfile prefix.')
parser.add_argument('-hostname', type=str, default='', help='Hostname/ip address to respond to, by default respond to all.')

args = parser.parse_args()
response = ''


logger = logging.getLogger()

logFileName = args.log+datetime.now().strftime("%d.%m.%-y-%H.%M.%S")+'.log'
logger.setLevel(logging.DEBUG)

log_format = '>%(asctime)s :\n%(message)s'
logging.basicConfig(filename=logFileName,format=log_format, datefmt='%Y-%m-%d %H:%M:%S')


if args.respond:
    response = bytes(args.respond, 'UTF8')

class myHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        logger.info(self.headers)
        self.send_response(args.c)
        if args.url:
            self.send_header('Location',args.url)
        self.end_headers()
        if response:
            self.wfile.write(response)
    def log_message(self, format, *args):
        logger.info("#%s - %s\n" % (self.client_address[0],format%args))


try:
    pywebserver = HTTPServer((args.hostname, args.p), myHandler)

    txt='Running '+args.hostname+' on port '+str(args.p)+' returning code '+str(args.c)
    
    if args.url:
        txt=txt+' and location to '+args.url

    if args.ssl:
        pywebserver.socket = ssl.wrap_socket (pywebserver.socket, 
            keyfile="local.key", 
            certfile='local.crt', server_side=True)
        txt=txt+' with SSL'
    
    if args.respond:
        txt=txt+' respond with >'+args.respond
    
    print(txt)

    logger.info(txt)

    pywebserver.serve_forever()


except KeyboardInterrupt:
    print('Interrupt received, shutting down the web server')
    pywebserver.socket.close()