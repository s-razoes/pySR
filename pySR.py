import http.server
import ssl
from http.server import HTTPServer
import logging
from datetime import datetime
import argparse

parser = argparse.ArgumentParser(prog='redirect')
parser.add_argument('-location', type=str, default='', help='Location to redirect to.')
parser.add_argument('-respond', type=str, default='', help='Body text to respond.')
parser.add_argument('-respondF', type=str, default='', help='File to respond.')
parser.add_argument('-p', type=int, default=8080, help='Port to serve [Default=8080]')
parser.add_argument('-c', type=int, default=200, help='HTTP code to return [Default=200]')
parser.add_argument('--cert', type=str, default='', help='Location of certificate file to use as public key in SSL connections')
parser.add_argument('--pKey', type=str, default='', help='Location of file to use as private key in SSL connections')
parser.add_argument('-log', type=str, default='', help='Logfile prefix.')
parser.add_argument('-hostname', type=str, default='', help='Hostname/ip address to respond to, by default respond to all.')

args = parser.parse_args()
response = ''


logger = logging.getLogger()

logFileName = args.log+datetime.now().strftime("%d.%m.%-y-%H.%M.%S")+'.log'
logger.setLevel(logging.DEBUG)

log_format = '>%(asctime)s :\n%(message)s'
logging.basicConfig(filename=logFileName,format=log_format, datefmt='%Y-%m-%d %H:%M:%S')

#check uncompatible arguments
if args.respond and args.respondF:
    print('Can only have one response argument')
    quit()

#has all the conditions for the certificates
if args.cert != '' or args.pKey != '':
    if args.cert == '' or args.pKey =='':
        print('When introducing certificates, both must be present')
        quit()

if args.respond:
    response = bytes(args.respond, 'UTF8')

if args.respondF:
    f = open(args.respondF, 'rb')
    response = f.read()
    f.close()

class myHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        logger.info(self.headers)
        self.send_response(args.c)
        if args.location:
            self.send_header('Location',args.location)
        self.end_headers()
        if response:
            self.wfile.write(response)
    def log_message(self, format, *args):
        logger.info("#%s - %s\n" % (self.client_address[0],format%args))


try:
    pywebserver = HTTPServer((args.hostname, args.p), myHandler)

    txt='Running '+args.hostname+' on port '+str(args.p)+' returning code '+str(args.c)
    
    if args.location:
        txt=txt+' and location to '+args.location

    if args.cert:
        pywebserver.socket = ssl.wrap_socket (pywebserver.socket, 
            keyfile=args.pKey, 
            certfile=args.cert, server_side=True)
        txt=txt+' with SSL'
    
    if args.respond:
        txt=txt+' respond with >'+args.respond
    
    if args.respondF:
        txt=txt+' respond with file '+args.respondF
    
    print(txt)

    logger.info(txt)

    pywebserver.serve_forever()


except KeyboardInterrupt:
    print('Interrupt received, shutting down the web server')
    pywebserver.socket.close()