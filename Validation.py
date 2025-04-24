
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
    def analyze_packets(self,report_file):
        ip_counter=Counter()

        #adding time sign to file report
        self.time_sign_to_file(REPORT_FILE_PATH)
        self.analyze_packets_flow()
        print(ip_counter)

    def analyze_packets_flow(self,ip_counter=Counter()):
        for pack in self.packest_list:
            block_flag=self.packet_blocked_check(pack)
            if block_flag:
                self.update_counter(ip_counter,pack,"block")
                self.print_message_2_file(pack, "block")
            else:
                allow_flag=self.packet_allow_check(pack)
                if allow_flag:
                    self.update_counter(ip_counter,pack,"valid")
                    self.print_message_2_file(pack, "valid")
            if not block_flag and not allow_flag:
                self.print_invalid_message(pack)
                self.update_counter(ip_counter,pack,"invalid")

    def time_sign_to_file(self,report_file):

        with open(report_file, "a", encoding="utf-8") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"\n=== Report started at {timestamp} ===\n")

    def packet_blocked_check(self,pack):
        if pack.source_ip in self.policy.blocked_sources:
            # TODO add flag of block packet
            pack.tag= "Block"
            print(f"-Packet #{pack.packet_num}: Blocked , source IP {pack.source_ip} is in blocked sources list")
            return True
        else:
            return False

    def packet_allow_check(self,pack):
        for rule in self.policy.allowed_routes:
            if pack.source_ip == rule['src_ip'] and pack.destination_ip == rule['dst_ip'] and pack.protocol== rule['protocol'] and pack.destination_port == rule['dst_port'] :
                pack.tag="Valid"
                print(f"Packet #{pack.packet_num} : valid {pack.protocol} flow from {pack.source_ip} to {pack.destination_ip} : {pack.destination_port} ")
                return True
        pack.tag= "Invalid"
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

    def update_counter(self,counter,pack,status):
        if status == "invalid":
            counter.update("invalid",pack.packet_num)
            return True

        if status == "valid":
            if pack.protocol =='TCP':
                counter.update("allow_TCP",pack.packet_num)
            elif pack.protocol == 'UDP':
                counter.update('allow_UDP',pack.packet_num)
            return True

        elif status == "block":
            if pack.protocol == 'TCP':
                counter.update("block_TCP",pack.packet_num)
            elif pack.protocol == 'UDP':
                counter.update('block_UDP',pack.packet_num)
            return True


