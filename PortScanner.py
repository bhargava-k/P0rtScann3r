from asyncio import proactor_events
from tkinter.messagebox import RETRY
from scapy.all import *

host = input("Host/ IP : ")

answer = input("Do you want to scan popular ports [25,80,53,443,445,8080,8443] Yes(Y) or No(N): ")
if answer == "Y" or "y":
    ports = [25,80,53,443,445,8080,8443]
elif answer == "N" or "n":
    a = input('Port Start:')
    c = int(a)
    b = input('Port End:')
    d = int(b)
    lst = list(range(c, d))
    ports = lst

else:
    print("Please enter yes or no.")

def SynScan(host):
    ans, unans = sr(IP(dst=host) / TCP(dport=ports, flags="S"), timeout=2, verbose=0)
    print("Open ports at %s:" % host)
    for (s, r,) in ans:
        if s[TCP].dport == r[TCP].sport:
            print(s[TCP].dport)


def DNSScan(host):
    ans, unans = sr(IP(dst=host) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="google.com")), timeout=2, verbose=0)
    if ans:
        print("DNS Server at %s" % host)
SynScan(host)
DNSScan(host)