
import Policy
import IP_Packet

class Validator:

    def __init__(self,policy,packtes_list):
        self.policy= policy
        self.packest_list=packtes_list




    def analyze_packets(self):
        for pack in self.packest_list:
            self.packet_blocked_check(pack)
            # if pack.source_ip in self.policy.blocked_sources:
            #     print(f"-Packet #{pack.packet_num}: Blocked , source IP {pack.source_ip} is in blocked sources list")
            #     #TODO add flag of block packet
            # self.policy.allowed_routes
            # print(self.policy.allowed_routes)

    def packet_blocked_check(self,pack):
        if pack.source_ip in self.policy.blocked_sources:
            print(f"-Packet #{pack.packet_num}: Blocked , source IP {pack.source_ip} is in blocked sources list")
            # TODO add flag of block packet
    