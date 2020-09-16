import http.server
import ssl
from http.server import HTTPServer
import logging
from datetime import datetime, timedelta
import argparse
import socket
import subprocess
import fnmatch
import mimetypes

serverSoftware = 'Noyb' #Return this in the server response... why?
#ok... want a better redirector that does all of this but more robust?
#not on your budget

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
parser.add_argument('-cmd', type=str, default='', help='Command to execute and return the result')
parser.add_argument('-cmdRT', type=int, default=0, help='Time interval where the cmd can execute again(0 to run aways... that is the default btw)')
parser.add_argument('-ipF', type=str, default='', help='Filter IP addresses that will only be replied to (comma separated, wildcards are accepted)')
parser.add_argument('-v6', action='store_true',help='IPv6 mode')
parser.add_argument('-ipRT', type=int, default=0, help='Limit in seconds a client can re-request(0 no limit, that is also the default)')

args = parser.parse_args()

#check uncompatible arguments
if args.respond and args.respondF:
    print('Can only have one response argument')
    quit()
#has all the conditions for the certificates
if args.cert != '' or args.pKey != '':
    if args.cert == '' or args.pKey =='':
        print('When introducing certificates, both must be present')
        quit()

IPsFilter = ''

if args.ipF:
    IPsFilter = args.ipF.split(',')
    IPsFilter = [x.strip() for x in IPsFilter]

responseType = 'text/html'
response = None

if args.respond:
    response = bytes(args.respond, 'UTF8')

if args.respondF:
    f = open(args.respondF, 'rb')
    response = f.read()
    f.close()
    responseType = mimetypes.guess_type(args.respondF)[0]

#time control for command to execute
timeToRun = None
#dictionary with ip tables
timeTable = {}

#logging set up
logger = logging.getLogger()
logFileName = args.log+datetime.now().strftime("%d.%m.%-y-%H.%M.%S")+'.log'
logger.setLevel(logging.DEBUG)
log_format = '%(asctime)s: %(message)s'
logging.basicConfig(filename=logFileName,format=log_format, datefmt='%Y-%m-%d %H:%M:%S')


class myHandler(http.server.SimpleHTTPRequestHandler):
    #this code is unreachable because the socked is never read from
    #leaving this for historic pourposes
    def do_GET(self):
        logger.info(self.headers)
        self.send_response(args.c)
        if args.location:
            self.send_header('Location',args.location)
        self.end_headers()
        if response:
            self.wfile.write(response)
        self.wfile.flush()
        self.close_connection = True
        return
    #end of unreachable code
    def log_message(self, format, *args):
        logger.info("#%s - %s\n" % (self.client_address[0],format%args))
        self.close_connection = True
        return
        
    def send_response(self, code, message=None):
        #self.log_request(code)
        self.request_version = 'HTTP/1.1'
        self.send_response_only(code, message)
        self.send_header('Server', serverSoftware)
        self.send_header('Date', self.date_time_string())
        return
    def handle_one_request(self):
        #is filter not allowed
        if args.ipF:
            passed = False
            for ipMatch in IPsFilter:
                if fnmatch.fnmatchcase(self.client_address[0],ipMatch):
                    passed = True
            if not passed:
                #not allowed, get out
                self.close_connection = True
                logger.info('Filtered: ' + str(self.client_address))
                return

        if args.ipRT > 0:
            if self.client_address[0] not in timeTable:
                timeTable[self.client_address[0]] = datetime.now() + timedelta(seconds = args.ipRT)
            else:
                if timeTable[self.client_address[0]] >=  datetime.now():
                    logger.info(str(self.client_address) + ' - limited response, closed connection')
                    self.close_connection = True
                    return
                else:
                    timeTable[self.client_address[0]] = datetime.now() + timedelta(seconds = args.ipRT)

        logger.info(str(self.client_address))
        self.send_response(args.c)

        if args.location:
            self.send_header('Location',args.location)

        self.send_header('content-type',responseType)
        global response

        if args.cmd:
            runNow = True
            if args.cmdRT > 0:
                global timeToRun
                if timeToRun is None or timeToRun < datetime.now() and args.cmdRT > 0:
                    timeToRun = datetime.now() + timedelta(seconds = args.cmdRT)
                    runNow = True
                else:
                    runNow = False
            if runNow:
                cmdR = '<html><head><title>{}</title></head><body><h1>{}</h1>{}</body></html>'
                result = ''
                try:
                    result = subprocess.check_output(args.cmd, shell=True, universal_newlines=True)
                except subprocess.CalledProcessError as ex:
                    result = str(ex)
                cmdR = cmdR.format(args.cmd,self.date_time_string(), result.replace('\n','<br><br>'))
                response = bytes(cmdR,'UTF8')

        if response:
            self.send_header('content-length',len(response))
        self.end_headers()
        if response:
            self.wfile.write(response)
        self.wfile.flush()
        self.close_connection = True
        return


class HTTPServerV6(HTTPServer):
    address_family = socket.AF_INET6

try:
    if args.v6:
        hostName = args.hostname
        if hostName == '':
            hostName = '::'
        pywebserver = HTTPServerV6((hostName, args.p), myHandler)
    else:
        pywebserver = HTTPServer((args.hostname, args.p), myHandler)

    pywebserver.socket.settimeout(0.1)

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
    
    #cycle because of Errno 104 - connection refused by peer
    while True:
        try:
            pywebserver.serve_forever()
        except Exception as e:
            logger.error('Exception:'+exc)

except KeyboardInterrupt:
    endStr = 'Interrupt received, shutting down the web server'
    print(endStr)
    logger.info(endStr)
    pywebserver.socket.close()

except Exception as exc:
    logger.error('Exception:'+exc)


logger.info('Ended!')
