# This script is used to test if the eBPF program is working properly.
from random import choice, randint
from socket import inet_ntoa
from struct import pack
from scapy.all import *

class PacketForger:
    def __init__(self, proxy_ip, pool_size=10):
        self.proxy_ip = proxy_ip
        self.IP_POOL_SIZE = pool_size
        self.ip_pool = self.generate_ip_pool(self.IP_POOL_SIZE)
    
    def generate_ip_pool(self, num) -> list:
        '''
        生成随机IP地址池
        '''
        ip_pool = []
        for _ in range(num):
            ip_pool.append(inet_ntoa(pack('>I', randint(1, 0xffffffff))))
        return ip_pool
    
    def forge(self, sport=80, dport=8090):
        '''
        伪造IP包
        '''
        src = choice(self.ip_pool)
        ip = IP(src=src, dst=self.proxy_ip)
        # 伪造TCP包
        tcp = TCP(sport=sport, dport=dport, flags='S')
        # 伪造IP包
        packet = ip/tcp
        return packet
    
def main():
    forger = PacketForger("127.0.0.1")
    print(forger.ip_pool)
    count = 1
    while True:
        packet = forger.forge()
        send(packet, verbose=0, iface="lo")
        print(f"Sent number {count} packets")
        count += 1

if __name__ == "__main__":
    main()