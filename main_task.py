
#pip install scapy

from scapy.all import rdpcap,IP, TCP, UDP
from IP_Packet import IP_Packet


def read_packets(packets):

    packets_list=[]
    print(packets)
    for i, packet in enumerate(packets):

        num=i+1
        flag_protocol= True
        # כתובת מקור ויעד (אם זו מנה מסוג IP)
        #TODO- add ignore ARP PACKETS
        if packet.haslayer("IP"):
            print(f"From: {packet['IP'].src} --> To: {packet['IP'].dst}")
            src_ip_packet=packet['IP'].src
            dst_ip_packet=packet['IP'].dst
            if TCP in packet:
                protocol_type= "TCP"
            elif UDP in packet:
                protocol_type= "UDP"
            else:
                protocol_type = "other"
                flag_protocol=False
            #create IP_packet object
            if flag_protocol:
                temp_pack=IP_Packet(num,src_ip_packet,dst_ip_packet,protocol_type)
                packets_list.append(temp_pack)
            #temp_pack.display_info()
    return packets_list

def main():
    packets = rdpcap('traffic.pcap')
    # מדפיס את מספר המנות בקובץ
    print(f"Total packets: {len(packets)}")

    p_l=read_packets(packets)
    for i in p_l:
        i.display_info()

main()
