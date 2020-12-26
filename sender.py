from scapy.all import sr1
import random

from scapy.layers.inet import IP, TCP


# def ip_address():
#     """ Get Destination IP Address. """
#     host = input("Enter Destination Address: ")
#     return host
#
#
# def port_number():
#     """ Get Destination Port Number. """
#     port = input("Enter Port Number: ")
#     return port


# IP Address and Port Number
print('-' * 100)
host = input("Enter Destination Address: ")
port = input("Enter Port Number: ")
while True:
    try:
        # Parameters
        message = input("Enter your message: ")
        # Change IP Address
        if 'ip' in message:
            host = input("Enter Destination Address: ")
            continue
        elif 'port' in message:
            port = input("Enter Port Number: ")
            continue
        # TCP Packet
        ip = IP(dst=host)
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

