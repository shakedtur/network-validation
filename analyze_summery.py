
class Counter:

    def __init__(self):
        self.authorized_TCP=0
        self.block_TCP=0
        self.authorized_UDP=0
        self.block_UDP=0
        self.IPv6=0
        self.ignore_packets=0
        self.total=0

    def update(self, packet_type):
        if not hasattr(self, packet_type):
            raise ValueError(f"Unknown packet type: {packet_type}")
        current_value = getattr(self, packet_type)
        setattr(self, packet_type, current_value + 1)
        self.total += 1

    def __repr__(self):
        return (
            f"allow_TCP: {self.authorized_TCP}, block_TCP: {self.block_TCP}, "
            f"allow_UDP: {self.authorized_UDP}, block_UDP: {self.block_UDP}, "
            f"IPv6: {self.IPv6}, ignore_packets: {self.ignore_packets}, total: {self.total}"
        )
