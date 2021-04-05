# quick_nmap
quick nmap wrapper in python

You can run this to scan a "large" network fast using nmap
it will run multiple options (arp, udp, tcp, fast scan, 1000 popular ports)
the longer you wait the more will be analysed but you can follow the results
in the host map

# quick run 
chmod 755 ./quick_nmap.py
./quick_nmap.py -r 10.1.0.0/23
