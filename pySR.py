#!/usr/bin/python3
import ssl
import logging
from datetime import datetime, timedelta
import argparse
import socket
from socket import *
import subprocess
import fnmatch
import mimetypes
import traceback
from http import HTTPStatus

serverSoftware = 'Noyb' #Return this in the server response... why?
#ok... want a better redirector that does all of this but more robust?
#not on your budget

parser = argparse.ArgumentParser(prog='redirect')
parser.add_argument('-location', type=str, default='', help='Location to redirect to.')
parser.add_argument('-sameURL', action='store_true', help='When new location, keep the path (the path and file name in this example: http://example.com/PATH/XXX.JPG, the default is no)')
parser.add_argument('-upgradeHost', action='store_true', help='With this option it will keep the path and subdomains and upgrade host to HTTPS')
parser.add_argument('-respond', type=str, default='', help='Body text to respond.')
parser.add_argument('-respondF', type=str, default='', help='File to respond.')
parser.add_argument('-p', type=int, default=8080, help='Port to serve [Default=8080]')
parser.add_argument('-c', type=int, default=200, help='HTTP code to return [Default=200]')
parser.add_argument('--cert', type=str, default='', help='Location of certificate file to use as public key in SSL connections')
parser.add_argument('--pKey', type=str, default='', help='Location of file to use as private key in SSL connections')
parser.add_argument('-log', type=str, default='', help='Logfile prefix. If none is set, no log file will be produced only printed out.')
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

if args.location and args.upgradeHost:
    print('upgradeHost and location are not compatible parameters')
    quit()
newLocation = ''

#if there is no code but it's to upgrade the host, then use http code 301 = redirect
HTTPCode = args.c
if args.upgradeHost and args.c == 200:
    HTTPCode = 301

try:
    HeaderFirstLine = 'HTTP/1.0 {} {}\r\n'.format(HTTPCode,HTTPStatus(HTTPCode).phrase)
except ValueError:
    print('Invalid HTTP Code: ' + HTTPCode)
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
responseLen = ''

if args.respond:
    response = bytes(args.respond, 'UTF8')

if args.respondF:
    f = open(args.respondF, 'rb')
    response = f.read()
    f.close()
    responseLen = str(len(response))
    responseType = mimetypes.guess_type(args.respondF)[0]

#time control for command to execute
timeToRun = None
#dictionary with ip tables
timeTable = {}

#save logs to a file
if args.log != '':
    #logging set up
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    log_format = '%(asctime)s: %(message)s'
    logFileName = args.log+datetime.now().strftime("%d.%m.%-y-%H.%M.%S")+'.log'
    logging.basicConfig(filename=logFileName,format=log_format, datefmt='%Y-%m-%d %H:%M:%S')

#definitions

def logMessage(level, str):
    if args.log != '':
        getattr(logger, level)(str)
    else:
        print('[{}]{}: {}'.format(datetime.now().strftime("%d.%m.%-y-%H.%M.%S"),level,str))

class NotAllowedException(Exception):
    """Not allowed to request here"""
    pass

class BadRequestException(Exception):
    """Request was not valid"""
    pass


#runtime code

try:
    netType = AF_INET
    if args.v6:
        hostName = args.hostname
        if hostName == '':
            hostName = '::'
        netType = AF_INET6
        
    serverSocket = socket(netType, SOCK_STREAM)

    txt='Running '+args.hostname+' on port '+str(args.p)+' returning code '+str(HTTPCode)
    
    if args.location:
        txt=txt+' and location to '+args.location
        newLocation = args.location
        #if ends with '/' then remove it
        if newLocation[-1] == '/':
            newLocation = newLocation[:len(newLocation)-1]
    
    if args.cert:
        serverSocket = ssl.wrap_socket (serverSocket, keyfile=args.pKey, certfile=args.cert, server_side=True, do_handshake_on_connect=True, suppress_ragged_eofs=True)
        txt=txt+' with SSL'
    
    #Prepare a sever socket
    serverSocket.bind(('', args.p))
    serverSocket.listen(10)
    
    if args.respond:
        txt=txt+' respond with >'+args.respond
    
    if args.respondF:
        txt=txt+' respond with file '+args.respondF
    
    print(txt)
    logMessage('info',txt)
    
    #serve until interrupted
    while True:
        try:
            connectionSocket, addr = serverSocket.accept()
        except ssl.SSLError:
            logMessage('error','Request and denied non-secure connection')
            continue
        except OSError as ex:#[Errno 0] Error
            logMessage('error','Accepting socket: ' + str(ex))
            continue
            
        try:
            bMessage = connectionSocket.recv(65536)
            message = bMessage.decode("utf-8")
            logMessage('info', str(addr) + '\r\n' + message)

            proceed = True
            header = None
            requestedPath = '/'
            requestType = None
            requestDict = {}
            
            #only if first 3 characters are GET_ then split until the HTTP            
            #try to extract the requested path
            #onyl try if it's bigger then GET / HTTP/1.1
            if len(message) > 14:
                lines = message.split('\r\n')
                #first line is the type of request
                reqLine = lines[0].strip().split(' ')
                
                if len(reqLine) >= 3:
                    requestType = reqLine[0].strip()
                    if requestType != 'GET' and requestType != 'POST':
                        raise BadRequestException('Request type not allowed:' + requestType)
                    requestedPath = reqLine[1]
                    #fill the rest of the request dictionary
                    for line in lines[1:]:
                        line = line.strip()
                        if line == '':
                            continue
                        head, value = line.split(': ',1)
                        requestDict[head] = value
                else:
                    raise BadRequestException('Don\'t understand what was requested.')
            else:
                raise BadRequestException('Invalid request')
            
            if args.upgradeHost and 'Host' in requestDict:
                #ends in port 80 then remove that
                if requestDict['Host'][-3:] == ':80':
                    requestDict['Host'] = requestDict['Host'][:3]
                newLocation = 'https://' + requestDict['Host']
                logMessage('info','Redirecting to ' + newLocation)
            
            #is filter not allowed
            if args.ipF:
                passed = False
                for ipMatch in IPsFilter:
                    if fnmatch.fnmatchcase(addr[0],ipMatch):
                        passed = True
                if not passed:
                    #not allowed, get out
                    #logMessage('info','Filtered: ' + str(addr))
                    raise NotAllowedException('Filtered: ' + str(addr))

            if args.ipRT > 0:
                if addr[0] not in timeTable:
                    timeTable[addr[0]] = datetime.now() + timedelta(seconds = args.ipRT)
                else:
                    if timeTable[addr[0]] >=  datetime.now():
                        raise NotAllowedException(str(addr) + ' - limited response, closed connection')
                        #proceed = False
                    else:
                        timeTable[addr[0]] = datetime.now() + timedelta(seconds = args.ipRT)
                        
            
            if proceed:
                #construct header
                header = HeaderFirstLine
                    
                #new location option
                if newLocation != '':
                    header += 'Location: '
                    #if it's to keep the path
                    if (args.sameURL or args.upgradeHost) and requestedPath != '/':
                        header += newLocation + requestedPath + '\r\n'
                    else:
                        header += newLocation + '\r\n'

                header += 'content-type: ' + responseType + '\r\n'
                header += 'Server: ' + serverSoftware + '\r\nConnection: close\r\n'
                #add size to header
                if responseLen != '':
                    header += 'content-length: ' + responseLen + '\r\n'
                #send this part already
                connectionSocket.send(bytes(header,'UTF8'))
                header = ''
                if args.cmd:
                    runNow = True
                    if args.cmdRT > 0:
                        if timeToRun is None or timeToRun < datetime.now() and args.cmdRT > 0:
                            timeToRun = datetime.now() + timedelta(seconds = args.cmdRT)
                            runNow = True
                        else:
                            runNow = False
                    if runNow:
                        cmdR = '<html><head><title>{}</title></head><body><h1>{}</h1><h2>{}</h2>{}</body></html>'
                        result = ''
                        try:
                            result = subprocess.check_output(args.cmd, shell=True, universal_newlines=True)
                        except subprocess.CalledProcessError as ex:
                            result = str(ex)
                        cmdR = cmdR.format(args.cmd,args.cmd,str(datetime.now()), result.replace('\n','<br>'))
                        response = bytes(cmdR,'UTF8')
                        #content should only exist when it's not here, so there you go
                        header = 'content-length: ' + str(len(response)) + '\r\n'
            
                #Send the content of the requested file to the client
                data = bytes(header +'\r\n','UTF8')
                if response:
                    data += response
                connectionSocket.send(data)
                
            connectionSocket.close()
        except IOError:
            logMessage('error', 'IO: {}'.format(str(Exc)))
        except Exception as Exc:
            logMessage('error', 'When replying: {}'.format(str(Exc)))
        except BadRequestException as Exc:
            logMessage('error', 'Bad request: {}'.format(str(Exc)))
        except NotAllowedException as Exc:
            logMessage('error', 'Not allowed: {}'.format(str(Exc)))
        except ConnectionResetError:
            logMessage('error', 'Closed connection before reply: {}'.format(str(addr)))
        finally:
            connectionSocket.close()

except KeyboardInterrupt:
    endStr = 'Interrupt received, shutting down the web server'
    print(endStr)
    logMessage('info',endStr)
except Exception as Exc:
    logMessage('error',''.join(traceback.format_exception(etype=type(Exc), value=Exc, tb=Exc.__traceback__)) )
finally:
    connectionSocket.close()
    serverSocket.close()

logMessage('info','Ended!')
