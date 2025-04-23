
#pip install scapy

from scapy.all import rdpcap,IP, TCP, UDP
from IP_Packet import IP_Packet, IP_Packet_Ports
import Policy
import Validation

def read_packets(packets):
    """return list of just IPV4 of UDP and TCP type packets"""
    packets_list=[]
    print(packets)
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
    return packets_list

def main():
    pcap_file_name='traffic.pcap'
    json_file= "policy.json"

    packets = rdpcap(pcap_file_name)
    # מדפיס את מספר המנות בקובץ
    print(f"Total packets: {len(packets)}")

    filterd_packets_list=read_packets(packets)
    for i in filterd_packets_list:
        print(i)
    print(f"len of filterd_packets_list = {len(filterd_packets_list)}")
    policy_rules=Policy.from_json_file(json_file)
    policy_rules.display_policy()

    print("valiatinnnnnnn")
    V=Validation.Validator(policy_rules,filterd_packets_list).analyze_packets()

main()
