import re
import signal
import subprocess
import sys
from argparse import ArgumentParser
from ipwhois import IPWhois
import ipaddress
from prettytable import PrettyTable

IP_REGEX = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

table = PrettyTable()
table.field_names = ["No", "IP", "AS", "Country", "Provider"]
table.align = "l"  # Выравнивание по левому краю
table.max_width = 20  # Максимальная ширина колонок


def signal_handler(*_):
    sys.exit(0)


def is_private(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def get_ip_info(ip: str) -> dict:
    ip_info = {
        'ip': ip,
        'asn': '-',
        'country': '-',
        'provider': '-'
    }
    if is_private(ip):
        return ip_info
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
    except Exception:
        return ip_info
    ip_info['asn'] = res.get('asn', '-')
    ip_info['country'] = res.get('asn_country_code', '-')
    network = res.get('network', {})
    ip_info['provider'] = network.get('name', '-')
    return ip_info


def tracert(host: str) -> str:
    result = subprocess.run(
        ['tracert', '-d', '-w', '100', host],
        capture_output=True,
        text=True,
        encoding='cp866'
    )
    return result.stdout


def parse_tracert_output(output: str) -> list:
    ips = []
    for line in output.split('\n'):
        line = line.strip()
        if '***' in line or 'Request timed out' in line:
            break
        match = re.search(IP_REGEX, line)
        if match:
            ips.append(match.group())
    return ips


def get_arg_parser() -> ArgumentParser:
    parser = ArgumentParser()
    parser.add_argument('host', help='IP address or domain name')
    return parser


def main():
    signal.signal(signal.SIGINT, signal_handler)
    args = get_arg_parser().parse_args()
    tracert_output = tracert(args.host)
    addresses = parse_tracert_output(tracert_output)

    table = PrettyTable()
    table.field_names = ["No", "IP", "AS", "Country", "Provider"]
    table.align = "l"

    for idx, ip in enumerate(addresses, 1):
        info = get_ip_info(ip)
        table.add_row([idx, info['ip'], info['asn'], info['country'], info['provider']])

    print(f'\nTracing route to "{args.host}":\n')
    print(table)
    print('\nTracing completed.')


if __name__ == '__main__':
    main()