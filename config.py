import argparse
import dns.zone
from ipaddress import ip_address

parser = argparse.ArgumentParser(description='DNS Server. xmochn00@stud.fit.vutbr.cz')
parser.add_argument('-m', '--mitm', nargs=1, metavar='IP', type=ip_address,
                   help='resolvuje kazdy dotaz na A a MX na zvolenou IP')
parser.add_argument('-p', '--port', default=53, type=int,
                   help='port na kterem bude server naslouchat, pokud parametr neni zadany, pouzije standardni (53)')
parser.add_argument('zonefile', type=open, nargs='?', help='zonefile to load')

args = parser.parse_args()

zones = []

if args.zonefile is not None:
    zones.append(dns.zone.from_file(args.zonefile, origin='.', check_origin=False))
