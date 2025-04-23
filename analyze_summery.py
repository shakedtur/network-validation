#singletone DP
class Counter:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Counter, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        # verify just one object exist
        if self._initialized:
            return
        self.allow_TCP = 0
        self.block_TCP = 0
        self.allow_UDP = 0
        self.block_UDP = 0
        self.IPv6 = 0
        self.ignore_packets = 0
        self.total = 0
        self._initialized = True

    def update(self, packet_type):
        if not hasattr(self, packet_type):
            raise ValueError(f"Unknown packet type: {packet_type}")
        setattr(self, packet_type, getattr(self, packet_type) + 1)
        self.total += 1

    def __repr__(self):
        return (
            f"allow_TCP: {self.allow_TCP}, block_TCP: {self.block_TCP}, "
            f"allow_UDP: {self.allow_UDP}, block_UDP: {self.block_UDP}, "
            f"IPv6: {self.IPv6}, ignore_packets: {self.ignore_packets}, total: {self.total}"
        )
