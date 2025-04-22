
import json


class Policy:
    def __init__(self, blocked_sources, allowed_routes):
        self.blocked_sources = blocked_sources
        self.allowed_routes = allowed_routes

    def display_policy(self):
        """מציג בצורה מסודרת את מדיניות הניתוב"""
        print("=== Blocked Sources ===")
        for ip in self.blocked_sources:
            print(f"- {ip}")

        print("\n=== Allowed Routes ===")
        for route in self.allowed_routes:
            print(f"- {route['protocol']} | {route['src_ip']} -> {route['dst_ip']} : {route['dst_port']}")

#static function
def from_json_file(file_path):
    """loading data from JSON file"""
    with open(file_path, 'r') as file:
        data = json.load(file)

    blocked_sources = data.get("blocked_sources", [])
    allowed_routes = data.get("allowed_routes", [])
    return Policy(blocked_sources, allowed_routes)
