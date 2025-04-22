
from IPAdress import IP

class IP_Packet:
    def __init__(self,num, source_ip, destination_ip, protocol, length="len test", data='test'):
        self.packet_num= num
        self.source_ip = IP.from_string(source_ip)
        self.destination_ip = IP.from_string(destination_ip)
        self.protocol = protocol
        self.length = length
        self.data = data

    def display_info(self):
        print("=== IP Packet Info ===")
        print(f"Packet #{self.packet_num}")
        print(f"Source IP:      {self.source_ip}")
        print(f"Destination IP: {self.destination_ip}")
        print(f"Protocol:       {self.protocol}")
        print(f"Length:         {self.length} bytes")
        print(f"Data:           {self.data}")
        print("======================")

