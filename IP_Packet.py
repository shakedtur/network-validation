
from IPAdress import IP


class IP_Packet:
    def __init__(self,num, source_ip, destination_ip, protocol, length="len test", data='test'):
        self.packet_num= num
        self.source_ip = IP.from_string(source_ip)
        self.destination_ip = IP.from_string(destination_ip)
        self.protocol = protocol
        self.length = length
        self.data = data
    # TODO add src/ des port number

    def display_info(self):
        print("=== IP Packet Info ===")
        print(f"Packet number  #{self.packet_num}")
        print(f"Source IP:      {self.source_ip}")
        print(f"Destination IP: {self.destination_ip}")
        print(f"Protocol:       {self.protocol}")
        print(f"Length:         {self.length} bytes")
        print(f"Data:           {self.data}")
        print("======================")

#ineratence class from IP_packet

class IP_Packet_Ports(IP_Packet):
    def __init__(self, num, source_ip, destination_ip, protocol, source_port, destination_port, length="len test", data='test'):
        super().__init__(num, source_ip, destination_ip, protocol, length, data)
        self.source_port = source_port
        self.destination_port = destination_port

    def __str__(self):
        return (
            "=== IP Packet Info ===\n"
            f"Packet number  #{self.packet_num}\n"
            f"Source IP:      {self.source_ip}:{self.source_port}\n"
            f"Destination IP: {self.destination_ip}:{self.destination_port}\n"
            f"Protocol:       {self.protocol}\n"
            f"Length:         {self.length} bytes\n"
            f"Data:           {self.data}\n"
            "======================"
        )

