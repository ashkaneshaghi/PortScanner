import nmap
import socket
import time

print("Welcome to Port Scanner - 2019 - Ashkan Es Haghi")
print("-" * 90)

target = input("Enter the Host Name you want to Scan for open Ports : ")
targetIp = socket.gethostbyname(target)

print("Choose Scan type for the Address : ", targetIp)
print("-" * 90)
resp = input("\n [1] - TCP SYN ACK \n [2] - TCP FIN \n [3] - TCP XMAS \n [4] - Vanilla TCP Connect Scan \n "
             "[5] - TCP NULL \n [6] - TCP ACK \n [7] - Fragmentation Scanning \n "
             "[8] - UDP \n [9] - Vulnerability Detection on specific Port \n")

scanner = nmap.PortScanner()

if resp != '9':
    print("-" * 60)
    print("Scanning has been successfully started on ", targetIp)
    print("-" * 60)
    print("Nmap version = ", scanner.nmap_version())

if resp == '1':
    scanner.scan(target, '1-1024', '-v -sS')
    print("Command : ", str(scanner.command_line()))
    print("Scan Type : TCP -", scanner.scaninfo()['tcp']['method'].upper() + "-ACK")
    print("Total Number of Ports to scan : ", scanner.scaninfo()['tcp']['services'])
    print("IP Status for ", targetIp, " : ", scanner[targetIp].state())
    print("-" * 60)
    print("Port Scan Report on ", targetIp)
    print("-" * 60)
    for op in scanner[targetIp]['tcp'].keys():
        print("Discovered Open Port : ", op, "\nStatus : ", scanner[targetIp]['tcp'][op]['state'].upper(),
              "\nService : ", scanner[targetIp]['tcp'][op]['name'].upper(), "\nReason : ",
              scanner[targetIp]['tcp'][op]['reason'].upper())
        print("-" * 60)
elif resp == '2':
    scanner.scan(target, '1-1024', '-v -sF -sV')
    print("Command : ", str(scanner.command_line()))
    print("Scan Type : TCP -", scanner.scaninfo()['tcp']['method'].upper())
    print("Total Number of Ports to scan : ", scanner.scaninfo()['tcp']['services'])
    print("IP Status for ", targetIp, " : ", scanner[targetIp].state())
    print("-" * 60)
    print("Port Scan Report on ", targetIp)
    print("-" * 60)
    for op in scanner[targetIp]['tcp'].keys():
        if scanner[targetIp]['tcp'][op]['state'] == 'open':
            print("Discovered Open Port : ", op, "\nStatus : ", scanner[targetIp]['tcp'][op]['state'].upper(),
                  "\nService : ", scanner[targetIp]['tcp'][op]['name'].upper(), "\nVersion : ",
                  scanner[targetIp]['tcp'][op]['version'].upper(), "\nReason : ",
                  scanner[targetIp]['tcp'][op]['reason'].upper())
            print("-" * 60)
elif resp == '3':
    scanner.scan(target, '1-1024', '-v -sX -sV')
    print("Command : ", str(scanner.command_line()))
    print("Scan Type : TCP - ", scanner.scaninfo()['tcp']['method'].upper())
    print("Total Number of Ports to scan : ", scanner.scaninfo()['tcp']['services'])
    print("IP Status for ", targetIp, " : ", scanner[targetIp].state())
    print("-" * 60)
    print("Port Scan Report on ", targetIp)
    print("-" * 60)
    for op in scanner[targetIp]['tcp'].keys():
        if scanner[targetIp]['tcp'][op]['state'] == 'open':
            print("Discovered Open Port : ", op, "\nStatus : ", scanner[targetIp]['tcp'][op]['state'].upper(),
                  "\nService : ", scanner[targetIp]['tcp'][op]['name'].upper(), "\nVersion : ",
                  scanner[targetIp]['tcp'][op]['version'].upper(), "\nReason : ",
                  scanner[targetIp]['tcp'][op]['reason'].upper())
            print("-" * 60)
elif resp == '4':
    scanner.scan(target, '1-1024', '-v -sT')
    print("Command : ", str(scanner.command_line()))
    print("Scan Type : TCP - ", scanner.scaninfo()['tcp']['method'].upper())
    print("Total Number of Ports to scan : ", scanner.scaninfo()['tcp']['services'])
    print("IP Status for ", targetIp, " : ", scanner[targetIp].state())
    print("-" * 60)
    print("Port Scan Report on ", targetIp)
    print("-" * 60)
    for op in scanner[targetIp]['tcp'].keys():
        if scanner[targetIp]['tcp'][op]['state'] == 'open':
            print("Discovered Open Port : ", op, "\nStatus : ", scanner[targetIp]['tcp'][op]['state'].upper(),
                  "\nService : ", scanner[targetIp]['tcp'][op]['name'].upper(), "\nReason : ",
                  scanner[targetIp]['tcp'][op]['reason'].upper())
            print("-" * 60)
elif resp == '5':
    scanner.scan(target, '1-1024', '-v -sN -sV')
    print("Command : ", str(scanner.command_line()))
    print("Scan Type : TCP - ", scanner.scaninfo()['tcp']['method'].upper())
    print("Total Number of Ports to scan : ", scanner.scaninfo()['tcp']['services'])
    print("IP Status for ", targetIp, " : ", scanner[targetIp].state())
    print("-" * 60)
    print("Port Scan Report on ", targetIp)
    print("-" * 60)
    for op in scanner[targetIp]['tcp'].keys():
        if scanner[targetIp]['tcp'][op]['state'] == 'open':
            print("Discovered Open Port : ", op, "\nStatus : ", scanner[targetIp]['tcp'][op]['state'].upper(),
                  "\nService : ", scanner[targetIp]['tcp'][op]['name'].upper(), "\nReason : ",
                  scanner[targetIp]['tcp'][op]['reason'].upper())
            print("-" * 60)
elif resp == '6':
    scanner.scan(target, '1-1024', '-v -sA')
    print("Command : ", str(scanner.command_line()))
    print("Scan Type : TCP - ", scanner.scaninfo()['tcp']['method'].upper())
    print("Total Number of Ports to scan : ", scanner.scaninfo()['tcp']['services'])
    print("IP Status for ", targetIp, " : ", scanner[targetIp].state())
    print("-" * 60)
    print("Port Scan Report on ", targetIp)
    print("-" * 60)
    for op in scanner[targetIp]['tcp'].keys():
        print("Discovered Open Port : ", op, "\nStatus : ", scanner[targetIp]['tcp'][op]['state'].upper(),
              "\nService : ", scanner[targetIp]['tcp'][op]['name'].upper(), "\nReason : ",
              scanner[targetIp]['tcp'][op]['reason'].upper())
        print("-" * 60)
elif resp == '7':
    scanner.scan(target, '1-1024', '-v -f -f -f')
    print("Command : ", str(scanner.command_line()))
    print("Scan Type : TCP - ", scanner.scaninfo()['tcp']['method'].upper())
    print("Total Number of Ports to scan : ", scanner.scaninfo()['tcp']['services'])
    print("IP Status for ", targetIp, " : ", scanner[targetIp].state())
    print("-" * 60)
    print("Port Scan Report on ", targetIp)
    print("-" * 60)
    for op in scanner[targetIp]['tcp'].keys():
        print("Discovered Open Port : ", op, "\nStatus : ", scanner[targetIp]['tcp'][op]['state'].upper(),
              "\nService : ", scanner[targetIp]['tcp'][op]['name'].upper(), "\nReason : ",
              scanner[targetIp]['tcp'][op]['reason'].upper())
        print("-" * 60)
elif resp == '8':
    scanner.scan(target, '1-1024', '-sU -v')
    print("Command : ", str(scanner.command_line()))
    print("Scan Type : ", scanner.scaninfo()['udp']['method'].upper())
    print("Total Number of Ports to scan : ", scanner.scaninfo()['udp']['services'])
    print("IP Status for ", targetIp, " : ", scanner[targetIp].state())
    print("-" * 60)
    print("Port Scan Report on ", targetIp)
    print("-" * 60)
    for op in scanner[targetIp]['udp'].keys():
        print("Discovered Open Port : ", op, "\nStatus : ", scanner[targetIp]['udp'][op]['state'].upper(),
              "\nService : ", scanner[targetIp]['udp'][op]['name'].upper(), "\nReason : ",
              scanner[targetIp]['udp'][op]['reason'].upper())
        print("-" * 60)
elif resp == '9':
    port = input("Enter the Port you want to check for vulnerability : ")
    print("-" * 60)
    print("Scanning has been successfully started on ", targetIp)
    print("-" * 60)
    print("Nmap version = ", scanner.nmap_version())
    scanner.scan(target, str(port), '-v -v -Pn --script vuln')
    print("Command : ", str(scanner.command_line()))
    print("Scan Type : TCP - ", scanner.scaninfo()['tcp']['method'].upper())
    print("Port to Scan for Vulnerability : ", scanner.scaninfo()['tcp']['services'])
    print("IP Status for ", targetIp, " : ", scanner[targetIp].state())
    print("-" * 60)
    print("Port Scan Report on ", targetIp)
    print("-" * 60)
    print("Port : ", port, "\nStatus : ", scanner[targetIp]['tcp'][int(port)]['state'].upper(),
          "\nService : ", scanner[targetIp]['tcp'][int(port)]['name'].upper(), "\nReason : ",
          scanner[targetIp]['tcp'][int(port)]['reason'].upper())
    print("=" * 60)
    print("Vulnerability Report on ", targetIp + ":" + port)
    print("=" * 60)
    for script in scanner[targetIp]['tcp'][int(port)]['script'].keys():
        print(script, ": |", scanner[targetIp]['tcp'][int(port)]['script'][script])



