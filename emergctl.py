#!/usr/bin/env python3
import argparse, socket

CTRL_IP   = "192.168.1.200"
CTRL_PORT = 9998

# İsim -> DPID (hex) haritan
NAME2DPID = {
    "pi1": "000000e04c680591",
    "pi2": "000000e04c680571",
    "pi3": "000000e04c68088f",
    "pi4": "000000e04c680796",
    "pi5": "000000e04c680783",
}

def norm_dpid(x: str) -> str:
    """pi-ismi veya decimal/hex DPID al, DECIMAL string döndür."""
    x = x.strip()
    key = x.lower()
    if key in NAME2DPID:  # 'pi1' gibi
        x = NAME2DPID[key]
    # decimal mi?
    try:
        int(x)
        return x  # zaten decimal string
    except ValueError:
        pass
    # hex -> decimal
    return str(int(x, 16))

def send(msg: bytes, ip=CTRL_IP, port=CTRL_PORT):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(msg, (ip, port))
    s.close()
    print(f"[sent] {msg!r} -> {ip}:{port}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Emergency control CLI (to controller)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    on  = sub.add_parser("on", help="Emergency ON between two nodes")
    on.add_argument("src", help="src dpid or name (e.g. pi1 or 963354... or 0x...)")
    on.add_argument("dst", help="dst dpid or name")

    off = sub.add_parser("off", help="Emergency OFF (global)")

    args = ap.parse_args()
    if args.cmd == "off":
        send(b"EMERG OFF")
    else:
        s = norm_dpid(args.src)
        d = norm_dpid(args.dst)
        payload = f"EMERG ON {s} {d}".encode("ascii")
        send(payload)
