
import Policy
import IP_Packet
from analyze_summery import Counter
from datetime import datetime
REPORT_FILE_PATH ="report.txt"

class Validator:

    def __init__(self,policy,packtes_list):
        self.policy= policy
        self.packest_list=packtes_list

    #TODO add color to messgages
    #TODO add counter summery
    def analyze_packets(self):
        #adding time sign to file report
        with open(REPORT_FILE_PATH, "a", encoding="utf-8") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"\n=== Report started at {timestamp} ===\n")

        for pack in self.packest_list:
            block_flag=self.packet_blocked_check(pack)
            if not block_flag:
                allow_flag=self.packet_allow_check(pack)
            if not block_flag and not allow_flag:
                self.print_invalid_message(pack)
#

    def packet_blocked_check(self,pack):
        if pack.source_ip in self.policy.blocked_sources:
            # TODO add flag of block packet
            pack.tag= "Block"
            print(f"-Packet #{pack.packet_num}: Blocked , source IP {pack.source_ip} is in blocked sources list")
            self.print_message_2_file(pack,"block")
            return True

        return False

    def packet_allow_check(self,pack):
        for role in self.policy.allowed_routes:
            if pack.source_ip == role['src_ip'] and pack.destination_ip == role['dst_ip'] and pack.protocol== role['protocol'] and pack.destination_port == role['dst_port'] :
                pack.tag="Valid"
                print(f"Packet #{pack.packet_num} : valid {pack.protocol} flow from {pack.source_ip} to {pack.destination_ip} : {pack.destination_port} ")
                self.print_message_2_file(pack,"valid")
                return True
        return False

    def print_invalid_message(self, pack):
        print(f"Packet #{pack.packet_num} : Invalid- no matching allowed route for  {pack.protocol} flow from {pack.source_ip} to {pack.destination_ip} : {pack.destination_port} ")
        self.print_message_2_file(pack,"invalid")

    def print_message_2_file(self, pack, status, file_path= REPORT_FILE_PATH):
        if status == "valid":
            message = f"Packet #{pack.packet_num}: ✅ valid {pack.protocol} flow from {pack.source_ip} to {pack.destination_ip} : {pack.destination_port} \n"

        elif status == "block":
            message = f"Packet #{pack.packet_num}: ❌ Blocked , source IP {pack.source_ip} is in blocked sources list\n"

        elif status == "invalid":
            message = f"Packet #{pack.packet_num}:⚠️Invalid- no matching allowed route for  {pack.protocol} flow from {pack.source_ip} to {pack.destination_ip} : {pack.destination_port} \n"

        else:
            message = f"Packet #{pack.packet_num} : Unknown status '{status}'\n"

        # write to report file by add a sentence
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(message)

    def update_counter(self,counter,pack,flag):
        pass

