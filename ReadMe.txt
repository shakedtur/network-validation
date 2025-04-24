#installing laybereis 
pip install scapy
pip install -U pytest

#run a code
python main_task.py

#run a testing code
python -m unittest TestFile.py


class structure:

project/
├── main.py
├── IP_Packet.py
	|-----IPAdress
├── policy.py
├── validator.py
├── counter.py
├── tests/
│   └── test_validator.py


assumptions:
every ip address is legal string with 4 occtats eash one is between 0 to 255
allow policy include 4 parameters source ip, destation ip, protocol -TCP/ UDP , ip port
