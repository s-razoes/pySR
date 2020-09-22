# pySR
Python3 HTTP/S server with log, redirect, command execution, IP filter, IPv6 support, IP timeout, simple file server

To keep it fast and mean, it was built from socket level up.


## Arguments:

* location - Location to redirect to.
* sameURL - When new location, keep the path (the path and file name in this example: http://example.com/PATH/XXX.JPG) [Default no]
* upgradeHost - With this option it will keep the path and subdomains and upgrade host to HTTPS [Default no]
* respond - Body text to respond.
* respondF - File to respond.
* p - Port to serve [Default=8080]
* c - HTTP code to return [Default=200]
* cert - Location of certificate file to use as public key in SSL connections
* pKey - Location of file to use as private key in SSL connections
* log - Logfile prefix. If none is present then will not produce log file and will output the messages instead.
* hostname - Hostname/ip address to respond to, by default respond to all.
* cmd - Command to execute and return the result
* cmdRT - Time interval where the cmd can execute again(0 to run aways... that is the default btw)
* ipF - Filter IP addresses that will only be replied to (comma separated, wildcards are accepted)
* v6 - IPv6 mode
* ipRT - Limit in seconds a client can re-request(0 no limit, that is also the default)

## Example of usage:

Respond with HTTP ok(200) on port 8080 and printout requests and only print out info:

`
python3 pySR.py
`

Redirect request(code 301) from port 80(HTTP) to 443(HTTPs) on the same host and parameters and store logs in file "upg(datetime).log":

`
python3 pySR.py -p 80 -upgradeHost -log upg
`

Redirect requests(code 301) from port 80(HTTP) to (https://example.com) and store logs in file "redirect(datetime).log":

`
python3 pySR.py -p 80 -c 301 -location https://example.com -log redirect
`

Show a simple page with SSL and store the logs in file "SSL(datetime).log":

`
python3 pySR.py -p 443 -respondF singlePage.html --cert cert.pem --pKey privkey.pem -log SSL
`

Show a page on port 8080 with SSL showing the current running python processes, only allow that command to execute every 10 seconds, run on IPv6, filter to accept only IPs that start with (2001::) or (2001:450:34f:f3:) and store the logs in file "PS(datetime).log":

`
python3 pySR.py -cmd 'ps x|grep python' -cmdRT 10 -p 8080 -v6 -ipF 2001::*,2001:450:34f:f3:* --cert cert.pem --pKey privkey.pem -log PS
`

Show a page on port 8080 with SSL showing the content of file PS17.09.20-09.39.37.log, block IPs from making the same request in less then 2 seconds and printout requests and and only print out info:

`
python3 pySR.py -cmd 'cat PS17.09.20-09.39.37.log' -p 8080 --cert cert.pem --pKey privkey.pem -ipRT 2
`


If you have any suggestions, please send me a message :)
