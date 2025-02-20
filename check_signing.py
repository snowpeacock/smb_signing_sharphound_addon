from impacket.smbconnection import SMBConnection
import argparse
import sys
import time
import random

# @snowpeacock
# Simple script to check if a remote SMB server requires signing
# Uses SMBv3, for SMBv1 use conn.isSigningRequired() (requires credentials)


def new_check_smb_signing(target, port=445, username="", password="", domain=""):
    try:
        conn = SMBConnection(target, target, None, port, timeout=5)
        if conn._SMBConnection._Connection["RequireSigning"]:
            return f"[SMB] Target {target} requires signing"
        else:
            return f"[SMB] Target {target} does not require signing"
    except Exception as e:
        return f"[ERR] Could not scan SMB signing of {target}. Error: {e}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check SMB Signing on multiple targets")
    parser.add_argument("file", help="File containing a list of IPs or hostnames (one per line)")
    parser.add_argument("--port", type=int, default=445, help="SMB port (default: 445)")
    parser.add_argument("--username", help="Username for SMB authentication", required=False, default="")
    parser.add_argument("--password", help="Password for SMB authentication", required=False, default="")
    parser.add_argument("--domain", help="Domain for SMB authentication", required=False, default="")
    parser.add_argument("--output", help="File to save results (optional)", required=False, default="")
    parser.add_argument("--delay", help="Delay between SMB connections", type=float, required=False, default=1)
    parser.add_argument("--jitter", help="Jitter between SMB connections", type=float, required=False, default=1)

    args = parser.parse_args()

    # Read targets
    try:
        with open(args.file, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[ERR] Could not read file {args.file}. Error: {e}")
        sys.exit(1)

    results = []

    print(f"[INF] Checking SMB Signing for {len(targets)} targets...")
    for target in targets:
        time.sleep(random.randint(args.delay * 1000, (args.delay + args.jitter) * 1000) / 1000)
        result = new_check_smb_signing(target, args.port, args.username, args.password, args.domain)
        results.append(result)
        print(result)

    # Save results
    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write("\n".join(results))
            print(f"[INF] Results saved to {args.output}")
        except Exception as e:
            print(f"[ERR] Could not save results to {args.output}. Error: {e}")
