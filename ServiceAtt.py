import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff,IP
from colorama import Fore
from logs import log_error,log_blacklist,log_event
import requests
import json
from firewall import *
#--------------------------------

THRESHOLD=40
info=Fore.GREEN+"info"+Fore.RESET
warming=Fore.RED+"WARMİNG"+Fore.RESET
error=Fore.RED+"error"+Fore.RESET
log_event("[info]START")
log_error("[error]not-is-error")
log_blacklist("127.0.0.1")
# artık
#  kayıt tutmaya hazırız.

print(f"[{info}]THRESHOLD:{THRESHOLD}")
def packet_caliback(packet):
    src_ip=packet[IP].src
    packet_count=[src_ip] =+1 # bura düzeltilecek
    current_time=time.time()
    time_intreval=int(current_time) - int(start_time[0])
    if time_intreval>=1:
        for ip,count in packet_count.itmes():
            packet_rate=count/time_intreval
            if packet_rate>THRESHOLD and ip not in blocked_ip:
                print("["+"="*20)
                print(f"[{warming}]BLOCKED_IP{ip},packet_rate{packet_rate}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                log_event(message)
                message=f"[warming]{ip}"
                log_blacklist(ip)
                blocked_ip.add(ip)
                ip_address=ip
                url = f"http://ip-api.com/json/{ip_address}?fields=66846719"  # fields=66846719 -> tüm veriler
                try:
                    response = requests.get(url, timeout=5)
                    data = response.json()

                    if data["status"] == "success":
                        a=print(f"[+] IP Address     : {data.get('query')}")
                        b=print(f"[+] Country        : {data.get('country')} ({data.get('countryCode')})")

                        
                        c=print(f"[+] Region         : {data.get('regionName')} ({data.get('region')})")
                       
                        d=print(f"[+] City           : {data.get('city')}")
                        
                        a2=print(f"[+] ZIP Code       : {data.get('zip')}")
                        
                        b2=print(f"[+] Latitude       : {data.get('lat')}")
                        
                        c2=print(f"[+] Longitude      : {data.get('lon')}")
                        
                        d2=print(f"[+] Timezone       : {data.get('timezone')}")
                        
                        a101=print(f"[+] ISP            : {data.get('isp')}")
                        
                        a102=print(f"[+] Organization   : {data.get('org')}")
                        
                        a103=print(f"[+] AS             : {data.get('as')}")
                        dtt=a+b+c+d+a2+b2+c2+d2+a101+a102+a103
                        log_event(dtt)
                    else:
                        er=print(f"[{error}] Error: {data.get('message')}")
                        log_error(er)
                except Exception as e:
                    print(f"[!] Exception occurred: {e}")
                    log_error(f"[!] Exception occurred: {e}")
            if is_nimda_worm(packet):
                print(f"{warming}BANNED Nimda source IP:{src_ip}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                log_event(f"{src_ip}:Nimda")
                log_blacklist({src_ip})
            if src_ip in blacklist:
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                log_event(f"{src_ip}:Banned")
                log_blacklist({src_ip})
#başa alınacak
            packet_count.clear()
            start_time[0]=current_time
    if __name__=="__name__":
        if os.geteuid()!=0:
            print(f"[{error}]NOT ROOT!!!!")
            log_error(f"[{error}]NOT ROOT!!!!")
            sys.exit()
        if os.name=="nt":
            print(f"[{error}]windows???")
            log_error(f"[{error}]windows???")
            sys.exit()
        packet_count=defaultdict(int)
        start_time=[time.time()]
        blocked_ip=set()
        print(f"[{info}]Monitoring_network_traffic...")
        sn=sniff(filter="ip",prn=packet_caliback)
        log_event(sn)
packet_caliback()


