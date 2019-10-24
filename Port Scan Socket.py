import socket
import threading
from queue import Queue
import time
print_lock = threading.Lock()

target = input("Enter the host name you want to Scan for Ports : ")

targetIp = socket.gethostbyname(target)

print("-" * 100)
print("Scanning for Open ports on :", targetIp, " has been successfully started")
print("-" * 100)


def port_scanner(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        con = s.connect((targetIp, port))
        with print_lock:
            print("Port ", port, "   Open")
        con.close()
    except:
        pass


def threader():
    while True:
        prt = q.get()
        port_scanner(prt)
        q.task_done()


q = Queue()

for x in range(500):
    t = threading.Thread(target=threader)
    t.daemon = True
    t.start()

#start = time.time()

for ports in range(1, 1025):
    q.put(ports)

q.join()

#print("Process time : ", time.time()-start)

