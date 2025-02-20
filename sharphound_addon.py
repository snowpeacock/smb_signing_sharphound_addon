import json
import sys
import argparse
import time
import random
from tqdm import tqdm

from impacket.smbconnection import SMBConnection

# Simple script to check add SMB signing in sharphound computer json
# Uses SMBv3, for SMBv1 use conn.isSigningRequired() (requires credentials)


def check_smb_signing(target, port=445, username="", password="", domain=""):
    try:
        conn = SMBConnection(target, target, None, port, timeout=5)
        return conn._SMBConnection._Connection["RequireSigning"]
    except Exception as e:
        print(f"[ERR] Could not scan SMB signing of {target}. Error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check SMB Signing on multiple targets")
    parser.add_argument("sharphound_computers_json", help="sharphound generated XXX_computers.json file")
    parser.add_argument("--port", type=int, default=445, help="SMB port (default: 445)")
    parser.add_argument("--username", help="Username for SMB authentication", required=False, default="")
    parser.add_argument("--password", help="Password for SMB authentication", required=False, default="")
    parser.add_argument("--domain", help="Domain for SMB authentication", required=False, default="")
    parser.add_argument("--output", help="File to save results (optional)", required=False, default="")
    parser.add_argument("--delay", help="Delay between SMB connections", type=float, required=False, default=1)
    parser.add_argument("--jitter", help="Jitter between SMB connections", type=float, required=False, default=1)

    args = parser.parse_args()

    # Parse sharphound-generated JSON
    try:
        computers_json = json.load(open(args.sharphound_computers_json))
    except Exception as e:
        print(e)
        sys.exit(1)

    # Loop through computers
    for computer_dic in tqdm(computers_json["data"]):
        computer_name = computer_dic["Properties"]["name"]

        # Chill a little
        time.sleep(random.randint(args.delay * 1000, (args.delay + args.jitter) * 1000) / 1000)
        result = check_smb_signing(computer_name, args.port, args.username, args.password, args.domain)
        if result is None:
            pass
        else:
            computer_dic["Properties"]["SMB_signing"] = result

    if args.output == "":
        output_name = args.sharphound_computers_json[:-5] + "_with_smb_signing" + ".json"
    else:
        output_name = args.output

    json.dump(computers_json, open(output_name, "w"))
