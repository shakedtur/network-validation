class IP:
    def __init__(self, octet1, octet2, octet3, octet4):
        self.octet1 = octet1
        self.octet2 = octet2
        self.octet3 = octet3
        self.octet4 = octet4

    def __str__(self):
        return f"{self.octet1}.{self.octet2}.{self.octet3}.{self.octet4}"

    def to_tuple(self):
        return (self.octet1, self.octet2, self.octet3, self.octet4)

    def to_int(self):
        """המרה לכתובת שלמה כמספר"""
        return (self.octet1 << 24) | (self.octet2 << 16) | (self.octet3 << 8) | self.octet4

    @staticmethod
    def from_string(ip_string):
        """קבלת אובייקט IP ממחרוזת"""
        octets = ip_string.split('.')
        if len(octets) != 4:
            raise ValueError("Invalid IP address format")
        return IP(int(octets[0]), int(octets[1]), int(octets[2]), int(octets[3]))

    def __eq__(self, other):
        if not isinstance(other, IP):
            return NotImplemented
        return self.to_tuple() == other.to_tuple()
