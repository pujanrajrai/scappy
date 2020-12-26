from scapy.all import sr1
import random

from scapy.layers.inet import IP, TCP


def ip_address():
    """ Get Destination IP Address. """
    host = input("Enter Destination Address: ")
    return host


def port_number():
    """ Get Destination Port Number. """
    port = input("Enter Port Number: ")
    return port


# IP Address and Port Number
print('-' * 100)
host = ip_address()
port = port_number()
while True:
    try:
        # Parameters
        message = input("Enter your message: ")
        # Change IP Address
        if 'ip' in message:
            host = ip_address()
            print(111)
            continue
        elif 'port' in message:
            port = port_number()
            print(11)
            continue
        # TCP Packet
        print(1)
        ip = IP(dst=host)
        print(1)
        tcp = TCP(sport=random.randint(10000, 65000), dport=int(port)) / message
        # Stack the packets
        packet = ip / tcp
        # Send the packet in the network
        print('-' * 100)
        sent = sr1(packet, timeout=5)
        try:
            # Received results
            print('-' * 100)
            print("Response")
            print('-' * 100)
            sent.show()
            print('-' * 100)
        except:
            # Neglate NONE Type 'sent' if there is no reply.
            pass
    except KeyboardInterrupt:
        print('')
        print('-' * 100)
        print('>>> Exiting ... <<<')
        print('-' * 100)
        break
    except Exception as e:
        print('')
        print('Exception:', e)
        print('')

