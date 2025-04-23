
import Policy
import IP_Packet

class Validator:

    def __init__(self,policy,packtes_list):
        self.policy= policy
        self.packest_list=packtes_list

    #TODO add color to messgages
    #TODO add counter summery
    def analyze_packets(self):
        for pack in self.packest_list:
            block_flag=self.packet_blocked_check(pack)
            allow_flag=self.packet_allow_check(pack)
            if not block_flag and not allow_flag:
                self.print_message(pack,"log.txt")
            # if pack.source_ip in self.policy.blocked_sources:
            #     print(f"-Packet #{pack.packet_num}: Blocked , source IP {pack.source_ip} is in blocked sources list")
            #     #TODO add flag of block packet
            # self.policy.allowed_routes
            # print(self.policy.allowed_routes)

    def packet_blocked_check(self,pack):
        if pack.source_ip in self.policy.blocked_sources:
            print(f"-Packet #{pack.packet_num}: Blocked , source IP {pack.source_ip} is in blocked sources list")
            return True
            # TODO add flag of block packet
        return False

    def packet_allow_check(self,pack):
        for role in self.policy.allowed_routes:
            if pack.source_ip == role['src_ip'] and pack.destination_ip == role['dst_ip'] and pack.protocol== role['protocol'] and pack.destination_port == role['dst_port'] :
                print(f"Packet #{pack.packet_num} : valid {pack.protocol} flow from {pack.source_ip} to {pack.destination_ip} : {pack.destination_port} ")
                return True
        return False

    def print_message(self,pack, pack_status):
        print(f"Packet #{pack.packet_num} : Invalid- no matching allowed route for  {pack.protocol} flow from {pack.source_ip} to {pack.destination_ip} : {pack.destination_port} ")



