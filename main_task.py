
#pip install scapy

from scapy.all import rdpcap,IP, TCP, UDP
from IP_Packet import IP_Packet, IP_Packet_Ports
import Policy
import Validation
from analyze_summery import Counter
PCAP_FILE = 'traffic.pcap'
JSON_FILE = "policy.json"

def filter_packets(packets):
    """return list of just IPV4 of UDP and TCP type packets"""
    packets_list=[]

    for i, packet in enumerate(packets):
        num=i+1
        flag_protocol= True
        # כתובת מקור ויעד (אם זו מנה מסוג IP)
        #TODO- add ignore ARP ICMP IPV6 PACKETS
        if packet.haslayer("IP"):
            print(f"From: {packet['IP'].src} --> To: {packet['IP'].dst}")
            src_ip_packet=packet['IP'].src
            dst_ip_packet=packet['IP'].dst
            if TCP in packet:
                protocol_type= "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol_type= "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            else:
                protocol_type = "other"
                flag_protocol=False
            #create IP_packet_port object
            if flag_protocol:
                temp_pack=IP_Packet_Ports(num,src_ip_packet,dst_ip_packet,protocol_type,src_port,dst_port)
                packets_list.append(temp_pack)
    print(f"Total packets read: {len(packets)}")
    return packets_list


def read_packets_from_PCAP_file(filename):
    packets_data = rdpcap(filename)
    print(packets_data)
    return packets_data



def main():


    packets = read_packets_from_PCAP_file(PCAP_FILE)

    filterd_packets_list=filter_packets(packets)

    print(f"len of filterd_packets_list = {len(filterd_packets_list)}")
    policy_rules=Policy.from_json_file(JSON_FILE)
    policy_rules.display_policy()

    print("valiadtion")
    V=Validation.Validator(policy_rules,filterd_packets_list).analyze_packets()

main()
