import argparse
import json
import os
import sys
import getpass
import ipaddress
import requests
from requests.auth import HTTPBasicAuth

def detect_if_type(intf: str) -> str:
    name = intf.lower()
    if name.startswith("loopback") or name.startswith("lo"):
        return "iana-if-type:softwareLoopback"
    return "iana-if-type:ethernetCsmacd"

def validate_ip_and_mask(ip: str, mask: str):
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        print(f"ERROR: Nieprawidłowy format IP: '{ip}'")
        sys.exit(4)

    try:
        ipaddress.IPv4Network(f"0.0.0.0/{mask}")
    except ValueError:
        print(f"ERROR: Nieprawidłowa maska podsieci: '{mask}'")
        sys.exit(4)

def build_payload(intf: str, desc: str, enabled: bool, ip: str, netmask: str) -> dict:
    return {
        "ietf-interfaces:interface": {
            "name": intf,
            "description": desc,
            "type": detect_if_type(intf),
            "enabled": enabled,
            "ietf-ip:ipv4": {
                "address": [
                    {
                        "ip": ip,
                        "netmask": netmask
                    }
                ]
            }
        }
    }

def main():
    parser = argparse.ArgumentParser(
        description="Configure Cisco IOS XE Interface via RESTCONF"
    )
    parser.add_argument("--host", default="10.10.20.48", help="Router IP")
    parser.add_argument("--user", default="developer", help="Username")
    parser.add_argument("--password", help="Password (optional, prompt if missing)")
    parser.add_argument("--intf", default="Loopback200", help="Interface name")
    parser.add_argument("--desc", default="Configured by Python RESTCONF")
    parser.add_argument("--ip", required=True, help="IP Address")
    parser.add_argument("--netmask", default="255.255.255.0", help="Subnet Mask")
    parser.add_argument("--shutdown", action="store_true", help="Disable interface")
    parser.add_argument("--verify-tls", action="store_true", help="Enable SSL verification")

    args = parser.parse_args()

    if not args.verify_tls:
        requests.packages.urllib3.disable_warnings()

    validate_ip_and_mask(args.ip, args.netmask)

    password = args.password or os.getenv("RESTCONF_PASSWORD")
    if not password:
        try:
            password = getpass.getpass(f"Podaj hasło dla {args.user}@{args.host}: ")
        except KeyboardInterrupt:
            print("\nAnulowano.")
            sys.exit(0)
    
    if not password:
        print("ERROR: Hasło jest wymagane.")
        sys.exit(3)

    base_url = f"https://{args.host}/restconf/data"
    url = f"{base_url}/ietf-interfaces:interfaces/interface={args.intf}"

    headers = {
        "Content-Type": "application/yang-data+json",
        "Accept": "application/yang-data+json",
    }

    payload = build_payload(
        intf=args.intf,
        desc=args.desc,
        enabled=not args.shutdown,
        ip=args.ip,
        netmask=args.netmask,
    )

    print(f"\n--- Konfiguracja: {args.intf} ({args.ip}/{args.netmask}) na {args.host} ---")

    try:
        response = requests.put(
            url,
            auth=HTTPBasicAuth(args.user, password),
            headers=headers,
            data=json.dumps(payload),
            verify=args.verify_tls,
            timeout=15
        )

        print(f"PUT Status: {response.status_code}")

        if response.status_code in (200, 201, 204):
            print("INFO: Konfiguracja przyjęta pomyślnie.")
        else:
            print("ERROR: Błąd konfiguracji.")
            print(f"Odpowiedź routera: {response.text}")
            sys.exit(1)

        print("\n--- Weryfikacja (GET) ---")
        get_response = requests.get(
            url,
            auth=HTTPBasicAuth(args.user, password),
            headers=headers,
            verify=args.verify_tls,
            timeout=15
        )

        if get_response.status_code == 200:
            print("SUCCESS! Dane interfejsu:")
            print(json.dumps(get_response.json(), indent=4))
        else:
            print(f"WARNING: PUT OK, ale GET zwrócił błąd: {get_response.status_code}")
            sys.exit(2)

    except requests.exceptions.SSLError:
        print("\n[BŁĄD SSL] Problem z certyfikatem lub wersją bibliotek SSL.")
        print("Spróbuj sprawdzić środowisko lub uruchom bez flagi --verify-tls (domyślne).")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        print(f"\n[BŁĄD SIECI] Nie można połączyć się z {args.host}.")
        print("Sprawdź: 1. VPN, 2. Czy IP routera jest poprawne.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[CRITICAL ERROR] {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
