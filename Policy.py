
import json

from IPAdress import IP

class Policy:
    def __init__(self, blocked_sources=[], allowed_routes={}):
        self.blocked_sources = self.convert_stringIP(blocked_sources)
        self.allowed_routes = self.convert_stringIP(allowed_routes)

    def display_policy(self):
        """מציג בצורה מסודרת את מדיניות הניתוב"""
        print("=== Blocked Sources ===")
        for ip in self.blocked_sources:
            print(f"- {ip}")

        print("\n=== Allowed Routes ===")
        for route in self.allowed_routes:
            print(f"- {route['protocol']} | {route['src_ip']} -> {route['dst_ip']} : {route['dst_port']}")

    # def convert_stringIP(self,ip_list):
    #     temp_list=[]
    #     for ip in ip_list:
    #         temp_list.append(IP.from_string(ip))
    #     return temp_list

    def convert_stringIP(self, ip_list):
        temp_list = []
        for ip in ip_list:
            if isinstance(ip, str):
                # אם מחרוזת — ממיר לאובייקט IP
                temp_list.append(IP.from_string(ip))
            elif isinstance(ip, dict):
                # אם מילון — מעדכן את השדות src_ip ו-dst_ip
                ip['src_ip'] = IP.from_string(ip['src_ip'])
                ip['dst_ip'] = IP.from_string(ip['dst_ip'])
                temp_list.append(ip)
            else:
                raise TypeError(f"Unsupported type in list: {type(ip)}")
        return temp_list

#static function
def from_json_file(file_path):
    """loading data from JSON file"""
    with open(file_path, 'r') as file:
        data = json.load(file)

    blocked_sources = data.get("blocked_sources", []) #list of blocked ip's
    allowed_routes = data.get("allowed_routes", []) #list of dict of allows rolls
    return Policy(blocked_sources, allowed_routes)
