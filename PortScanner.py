#!/usr/bin/python3

from ast import Break
from socket import *
from threading import *
import optparse
import pyfiglet as pfg
from datetime import *
import time, nmap
def livehosts():
    #find own ipaddress
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(('10.0.0.0',0))
    IP=s.getsockname()[0]
    s.close()#close the connection or socket 
    print('my ip : ',IP)
    ip=IP.split('.')

    #----------------------------------------------------------------------
    def classfinder(ip):
        if ip[0]>='0' and ip[0]<='127': return 'A'
        elif ip[0]>='128' and ip[0]<='191': return 'B' 
        elif ip[0]>='192' and ip[0]<='223': return 'C'
        elif ip[0]>='224' and ip[0]<='239': return 'D'
        else: return 'E' 
    print('Your IP belong to Class :', classfinder(ip))
    #----------------------------------------------------------------------
    # find the up hosts
    nm=nmap.PortScanner()
    nm.scan(hosts=ip[0]+'.'+ip[1]+'.'+ip[2]+'.'+'0'+'/24', arguments='-sP')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    for host, status in hosts_list:
        print('Host : {} '.format(host))
        print('state: {}'.format(status))

def connscan(tgtHost, tgtPort):    
    
    try:        
        sock=socket(AF_INET,SOCK_STREAM)
        sock.connect((tgtHost,tgtPort))
        print('[+] {}/tcp Open.'.format(tgtPort))
        
    except:
        print('[-] {}/tcp Close.'.format(tgtPort))
    
    finally:
        sock.close()
    
def Scan(tgtHost,tgtPort):
    try:
        tgtip=gethostbyname(tgtHost)
    except:
        print('Unknown Host {}'.format(tgtHost))
    try:
        tgtName=gethostbyaddr(tgtip)
        print('[+] Scan Results for: '+tgtName[2])
    except:
        print('[+] Scan Result for: '+tgtip)
    setdefaulttimeout(1)
    for tgtport in tgtPort:
        tgtport=int(tgtport)
        th=Thread(target=connscan, args=(tgtHost,tgtport))
        th.start()

def rangeScan(tgtHost,strtPort,endPort):
    try:
        tgtip=gethostbyname(tgtHost)
    except:
        print('Unknown Host {}'.format(tgtHost))
    try:
        tgtName=gethostbyaddr(tgtip)
        print('[+] Scan Results for: '+tgtName[2])
    except:
        print('[+] Scan Result for: '+tgtip)
    setdefaulttimeout(1)
    for tgtport in range(strtPort,endPort+1):
            th = Thread(target=connscan,args=(tgtHost,tgtport))
            th.start()

def main():
    print(pfg.figlet_format("PORT SCANNER",font="slant"))
    print(" "*56,"By Abdul Ahad")
    print("-"*70)
    print("Scanning Started at: "+ str(datetime.now()))
        
    parser=optparse.OptionParser('Usage of Port Scanner: '+ './PortScanner.py -H<targethost> -p<targetports>')
    parser.add_option('-l',dest='livehost',action='store_true',help='Specify all the live Hosts in the network.')
    parser.add_option('-H',dest='tgtHost',type='string',help='Specify target host')
    parser.add_option('-p',dest='tgtPort',type='string',help='Specify target ports seperateed by comma')
    parser.add_option("--pr", dest="port_range",type='string',default="1-65535", help="Port range to scan, default is 1-65535 (all ports)")
    
    (options,args) = parser.parse_args()
    livehost, tgtHost, tgtPorts, port_range = options.livehost, options.tgtHost, options.tgtPort, options.port_range
   

    start_time=time.time()
    if livehost:
        livehosts()
        Break
        
    elif tgtPorts:
        tgtPort=tgtPorts.split(',')
        Scan(tgtHost,tgtPort)
        Break 
    
    elif port_range:
        strtPort, endPort = port_range.split("-")
        strtPort, endPort = int(strtPort), int(endPort)
        rangeScan(tgtHost,strtPort,endPort)
        Break
    
    else:
        print("argument error")
        print(parser.usage)
        exit(0) 
    end_time=time.time()
    
    print("Time elapsed: ",end_time-start_time)

if __name__=="__main__":
    main()

    