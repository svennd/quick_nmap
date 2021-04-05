#!/usr/bin/python3
# written by : SvennD
# use : you can run this to scan a "large" network fast using nmap
#       it will run multiple options (arp, udp, tcp, fast scan, 1000 popular ports)
#       the longer you wait the more will be analysed but you can follow the results
#       in the host map
#
# example : ./quick_nmap.py -r 10.1.0.0/23


import os
import time
import glob
import requests
import datetime
import sys, getopt

# http://jodies.de/ipcalc
# in case of 128 / 25
# in case of 63 / 26
range="10.11.0.0-100"

# default
host_file = "results/hosts"

# options 
short_options = "fuhr:"
long_options = ["force", "no_udp", "help", "range"]

# settings
udp = True
force = False

# do a really quick run
def limited_tcp_nmap():
    global host_file
    global force
    file1 = open(host_file, 'r')
    for line in file1:
        if not os.path.isfile('results/nmap/%s.quick' % line.strip()) or force == True:
            os.system('nmap -n -sS -T4 -F -oG - %s > results/nmap/%s.quick & ' % (line.strip(), line.strip()))
    file1.close()
    print("\t[+] started fast TCP scan" )
    
# do a really quick run
def limited_udp_nmap():
    global host_file
    global force
    file1 = open(host_file, 'r')
    for line in file1:
        if not os.path.isfile('results/nmap/%s.udp' % line.strip()) or force == True:
            os.system('nmap -n -sU -T4 -F -oG - %s > results/nmap/%s.udp & ' % (line.strip(), line.strip()))
    file1.close()
    print("\t[+] started fast UDP scan" )
    
# do a normal run
def top1000_tcp_nmap():
    global host_file
    global force
    file1 = open(host_file, 'r')
    for line in file1:
        if not os.path.isfile('results/nmap/details/%s.tcp' % line.strip()) or force == True:
            os.system('nmap -sS -sV -T3 -oG - -oN results/nmap/details/%s.tcp %s > results/nmap/%s.tcp & ' % (line.strip(), line.strip(), line.strip()))
    file1.close()
    print("\t[+] started top 1000 TCP scan")
    
# do a normal run
def top1000_udp_nmap():
    global host_file
    global force
    file1 = open(host_file, 'r')
    for line in file1:
        if not os.path.isfile('results/nmap/details/%s.udp' % line.strip()) or force == True:
            os.system('nmap -sU -sV -T3 -oN results/nmap/details/%s.udp %s > /dev/null 2>&1 & ' % (line.strip(), line.strip()))
    file1.close()
    print("\t[+] started top 1000 UDP scan")
   
# check hosts (for alive)
# create a index file with only the ips
def detect_hosts():
    global range
    global host_file

    # scan the range
    os.system('nmap -n -sP -PR %s | grep for | cut -c 22- > %s' % (range, host_file))
    
    # create a subdir for each
    host_list = open(host_file, 'r')
    
    count = 0
    for line in host_list:
        count += 1
        host = line.strip()
        os.system('mkdir -p results/host/%s' % host)
    host_list.close()
    
    print("\t[=] found \033[1m\033[31m%s\033[37m\033[0m active hosts!" % str(count))

def possible_website(ip, port):
    if os.path.isfile('results/host/%s/website' % ip):
       return 1;
    else:
       # print("\t[+]checking website on %s" % ip)
       # check if we can detect information on the website stack
       os.system('whatweb %s:%s > results/host/%s/website &' % (ip, port, ip))
  
def possible_ssh(ip):
    if os.path.isfile('results/host/%s/ssh' % ip):
       return 1;
    else:
       # scan with default script
       os.system('nmap -n -sV -sC -p 22 %s > results/host/%s/ssh &' % (ip, ip))

def possible_vnc(ip):
    if os.path.isfile('results/host/%s/vnc' % ip):
       return 1;
    else:
       # scan with default script
       os.system('nmap -n --script vnc-info,realvnc-auth-bypass,vnc-title -p 5900 %s > results/host/%s/vnc &' % (ip, ip))
    
def possible_nfs(ip):
    if os.path.isfile('results/host/%s/nfs' % ip):
       return 1;
    else:
       # scan with default script
       os.system('showmount -e %s > results/host/%s/nfs &' % (ip, ip))
    
def possible_snmp(ip):
    if os.path.isfile('results/host/%s/snmp' % ip):
       return 1;
    else:
       # scan with default script
       os.system('snmp-check %s > results/host/%s/snmp &' % (ip, ip))
 
def check_port_functions (port, ip):
    if (port == "22"):
        possible_ssh(ip)
    elif (port == "80"):
        possible_website(ip, port)
    elif (port == "161"):
        possible_snmp(ip)
    elif (port == "443"):
        possible_website(ip, port)
    elif (port == "2049"):
        possible_nfs(ip)
    elif (port == "5900"):
        possible_vnc(ip)
    elif (port == "8080"):
        possible_website(ip, port)

def parse_nmap():
    for name in glob.glob('results/nmap/*.*'):
        # print(name)
        file = open(name, 'r')
        
        # get file only (remove path)
        filename = name.split("/")[-1]
        # remove extension
        host_ip = '.'.join(filename.split(".")[:-1])
        for line in file:
            host_info = line.split(',')
            if (len(host_info) > 2):   
                for port in host_info:
                    port_detail = port.split('/')
                    # valid port
                    if len(port_detail) > 3:
                        # in the first case we have to deal with host %ip ()\t Ports : 
                        if (len(port_detail[0]) > 6):
                            fix = port_detail[0].split(':')
                            port_detail[0] = fix[-1]
                        
                        check_port_functions(port_detail[0].strip(), host_ip)
        file.close();

def report_parse_ports(file, fallback=False):
    file = open(file, "r")
    
    content = ""
    count = 0
    for line in file:
        host_info = line.split(',')
        # skip if more then 25 ports
        # and we are in "fallback" mode
        if fallback == True and count > 25:
            continue
        if (len(host_info) > 2):   
            for port in host_info:
                port_detail = port.split('/')
                # valid port
                if len(port_detail) > 3:
                    # in the first case we have to deal with host %ip ()\t Ports : 
                    if (len(port_detail[0]) > 6):
                        fix = port_detail[0].split(':')
                        port_detail[0] = fix[-1]
                    content += "\t%s\t\t%s\t\t%s\n" % (port_detail[0].strip(), port_detail[4].strip(), port_detail[2].strip())
                    count += 1 
    file.close()
    if (count == 0):
        return False
    return [count, content]
    
def generate_report(endless = False):
    global host_file
    
    f = open("results/report.md", "w")
    
    # get all websites
    f.write("# websites\n")
    for name in glob.glob('results/host/*/website'):
        # print(name)
        file = open(name, 'r')
        
        # get file only (remove path)
        host_ip = name.split("/")[-2]
        
        f.write("##%s\n" % host_ip)
        for line in file:
            f.write("\t%s\n" % line)
        f.write("\n")
        file.close();
    
    f.write("\n")
    
    # get all hosts
    host_list = open(host_file, 'r')
    for line in host_list:
        host_ip = line.strip()
        f.write("#"*50)
        f.write("\n# host : %s\n" % host_ip)
        
        # TCP ports
        if os.path.isfile('results/nmap/%s.tcp' % host_ip):
            result = report_parse_ports('results/nmap/%s.tcp' % host_ip)
            is_full_report = 0
            if (result):    
                # if more then 25 show the quick one
                # and link to the full result file
                if (int(result[0]) < 25):
                    f.write("open TCP ports (%s) :\n" % result[0])
                    f.write(result[1])
                    is_full_report = 1
                else:
                    quick = report_parse_ports('results/nmap/%s.quick' % host_ip, fallback=True)
                    if (quick):
                        if (int(quick[0]) < 25):
                            f.write("PARTIAL open TCP ports (%s) :\n" % result[0])
                            f.write(quick[1])
            if is_full_report:
                f.write("original : \033[1m\033[32mresults/nmap/details/%s.tcp\033[37m\033[0m\n" % host_ip)
            else:
                f.write("full result : \033[1m\033[31mresults/nmap/details/%s.tcp\033[37m\033[0m\n" % host_ip)
            
        # no full TCP available yet  
        elif os.path.isfile('results/nmap/%s.quick' % host_ip):
            result = report_parse_ports('results/nmap/%s.quick' % host_ip)
            if (result):
                if (int(result[0]) < 25):
                    f.write("open TCP ports (%s) :\n" % result[0])
                    f.write(result[1])
                else:
                    f.write("see : results/nmap/%s.quick\n" % host_ip)
            
        # UDP
        if os.path.isfile('results/nmap/%s.udp' % host_ip):
            result = report_parse_ports('results/nmap/%s.udp' % host_ip)
            if (result):
                if (int(result[0]) < 25):
                    f.write("open UDP ports (%s) :\n" % result[0])
                    f.write(result[1])
                else:
                    f.write("see : results/nmap/%s.udp\n" % host_ip)
        
        # applications
        for name in glob.glob('results/host/%s/*' % host_ip):
        
            file = open(name, 'r')
            
            # get file only (remove path)
            application = name.split("/")[-1]
            
            # skip website since we do that first
            if application == "website":
                continue;
                
            if application == "snmp":
                f.write("## %s\n" % application)
                f.write("\tsee : %s" % name)
                continue;
                
            f.write("## %s\n" % application)
            for line in file:
                f.write("\t%s" % line)
            f.write("\n")
            file.close();

        f.write("\n\n")    
    host_list.close()
        
    f.close();
    
    if (endless):
        x = datetime.datetime.now()
        print("\t[=] report generated on %s : \033[32mresults/report.md\033[37m \r" % x , end='')
    else:
        print("[=] wip report : \033[32mresults/report.md\033[37m")

def main(argv):
    
    global force
    global udp
    global short_options
    global long_options
    global range
    
    try:
        arguments, values = getopt.getopt(argv, short_options, long_options)
    except getopt.error as err:
        # Output error, and return with an error code
        print (str(err))
        print('quick_nmap.py [OPTIONS] -r 10.11.0.1/26')
        print('\t-f, --force\t\tforce update and ignore existing files')
        print('\t-u, --no_udp\t\tdon\'t run anything on UDP protocol')
        print('\t-h, --help\t\ttthis is it.')
        sys.exit(2)
        
    for opt, arg in arguments:
      if opt in ("-h", "--help"):
         print('quick_nmap.py [OPTIONS]')
         print('\t-r, --range\t\trange format accepted by nmap; eg 10.1.0.1/23 or 10.1.0.1-100')
         print('\t-f, --force\t\tforce update and ignore existing files')
         print('\t-u, --no_udp\t\tdon\'t run anything on UDP protocol')
         print('\t-h, --help\t\ttthis is it.')
         
         sys.exit()
      elif opt in ("-r", "--range"):
        range = arg
      elif opt in ("-f", "--force"):
        force = True
      elif opt in ("-u", "--no_udp"):
        udp = False
    
    os.system('mkdir -p results/nmap/details')
    
    print("[+] detect all alive hosts in range : %s " % range)
    detect_hosts()
    
    # start tcp & udp nmap in fast mode (top 100)
    limited_tcp_nmap()  
    if udp:
        limited_udp_nmap()
    
    # give some time to finish & generate initial report
    time.sleep(1)
    generate_report()
    
    print("[+] starting slower scans")
    
    # start application hunting based on the quick result
    parse_nmap()
    time.sleep(3)
    
    # start top port scan (1000 ports/host)
    top1000_tcp_nmap()
    if udp:
       top1000_udp_nmap()
    
    time.sleep(5)
  
    print("[+] press control-C to exit (this will keep updating as we have no idea when this is finished)")
    try:
        while True:
            time.sleep(2)
            parse_nmap()
            time.sleep(3)
            generate_report(True)
    except KeyboardInterrupt:
        print("\ngoodbye cruel world. ;-)")

   
if __name__ == "__main__":
   main(sys.argv[1:])