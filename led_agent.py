#!/usr/bin/env python3
# led_agent.py  (explicit-iface only, robust; filters to Ryu LLDP with "dpid:")
# Deps (Ubuntu on Pi):
#   sudo apt-get update
#   sudo apt-get install -y python3-gpiozero python3-scapy
#
# Run (explicit multiple ifaces):
#   sudo -E python3 led_agent.py --iface eth0 --iface enx00e04c680591 --iface enx00e04c680796
#
# Optional:
#   --lldp-window 4 --down-grace 0.5         # tune LED responsiveness
#   --debug-lldp-ages                        # show per-iface LLDP ages every 2s
#   --accept-any-lldp                        # (TEMP) count any LLDP, not just Ryu
#
# Emergency override test:
#   echo -n "EMERG 1" | nc -u <pi_ip> 9999    # RED solid (emergency ON)
#   echo -n "EMERG 0" | nc -u <pi_ip> 9999    # back to LLDP logic

import argparse
import threading
import socket
import time
import signal
import sys
from typing import Optional, List

from gpiozero import LED
from scapy.all import AsyncSniffer, Ether  # LLDP: ethertype 0x88cc

# ------------------- Config -------------------
GREEN_PIN = 17
RED_PIN   = 27

LLDP_ETHERTYPE = 0x88CC
LLDP_OK_WINDOW_SEC = 4.0    # consider "connected" if LLDP seen within this window
DOWN_GRACE_SEC    = 0.5     # small hysteresis before turning RED
RENDER_PERIOD_SEC = 0.20    # LED renderer loop interval

EMERG_UDP_PORT = 9999
EMERG_ON_STRINGS  = {"EMERG 1", "EMERGENCY 1", "EMERGENCY ON", "EMERG ON", "ON"}
EMERG_OFF_STRINGS = {"EMERG 0", "EMERGENCY 0", "EMERGENCY OFF", "EMERG OFF", "OFF"}

# ------------------- State -------------------
last_lldp_seen_lock = threading.Lock()
last_lldp_seen: Optional[float] = None

per_iface_lock = threading.Lock()
last_lldp_per_iface: dict[str, Optional[float]] = {}

emergency_lock = threading.Lock()
emergency = False

stop_event = threading.Event()

# CLI flags (set in main)
IFACES: List[str] = []
ACCEPT_ANY_LLDP: bool = False
DEBUG_LLDP_AGES: bool = False

# LEDs
green = LED(GREEN_PIN)
red   = LED(RED_PIN)

def set_green(mode: str):
    if mode == "off":
        green.off()
    elif mode == "solid":
        green.on()
    elif mode == "blink_slow":
        green.blink(on_time=0.5, off_time=0.5, background=True)
    else:
        green.off()

def set_red(mode: str):
    if mode == "off":
        red.off()
    elif mode == "solid":
        red.on()
    elif mode == "blink_slow":
        red.blink(on_time=0.5, off_time=0.5, background=True)
    else:
        red.off()

def compute_led_modes(now: float):
    # priority: emergency > connected > disconnected
    with emergency_lock:
        if emergency:
            return ("off", "solid")
    with last_lldp_seen_lock:
        seen = last_lldp_seen
    connected = (seen is not None) and ((now - seen) <= LLDP_OK_WINDOW_SEC)
    if connected:
        return ("solid", "off")
    else:
        return ("off", "blink_slow")

# ------------------- Threads -------------------
def lldp_sniffer():
    """
    Each iface gets its own AsyncSniffer. We track last LLDP per iface.
    Only counts LLDP frames that look like Ryu topo probes (payload contains b"dpid:"),
    unless --accept-any-lldp is given.
    """
    def on_pkt(pkt, iface_name: str):
        if not pkt.haslayer(Ether):
            return
        eth = pkt[Ether]
        if eth.type != LLDP_ETHERTYPE:
            return

        if not ACCEPT_ANY_LLDP:
            # Ryu topo LLDP payload includes ASCII "dpid:"
            raw = bytes(pkt)
            if b"dpid:" not in raw:
                return

        now = time.time()
        with last_lldp_seen_lock:
            global last_lldp_seen
            last_lldp_seen = now
        with per_iface_lock:
            last_lldp_per_iface[iface_name] = now

    if not IFACES:
        print("[ERR] No --iface provided; pass physical NICs explicitly "
              "(e.g., --iface eth0 --iface enx...)")
        stop_event.set()
        return

    # Filter out obvious virtuals if user passed by mistake
    bad_prefixes = ("br-", "ovs-system", "lo")
    chosen = [i for i in IFACES if not any(i.startswith(p) for p in bad_prefixes)]
    if not chosen:
        print("[ERR] All provided IFACES were filtered out (virtual/loopback). Provide physical NICs.")
        stop_event.set()
        return

    print(f"[BOOT] Sniffing LLDP on IFACES={chosen}  (accept_any={ACCEPT_ANY_LLDP})")

    sniffers = []
    try:
        for iface in chosen:
            with per_iface_lock:
                last_lldp_per_iface.setdefault(iface, None)
            s = AsyncSniffer(
                iface=iface,
                filter="ether proto 0x88cc",
                store=False,
                prn=lambda pkt, _iface=iface: on_pkt(pkt, _iface),
                promisc=True,
            )
            s.daemon = True
            s.start()
            sniffers.append(s)

        while not stop_event.is_set():
            time.sleep(0.5)

    except Exception as e:
        print(f"[ERR] LLDP sniffer error: {e}")
    finally:
        for s in sniffers:
            try:
                s.stop()
            except Exception:
                pass

def emergency_listener():
    global emergency
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", EMERG_UDP_PORT))
    sock.settimeout(1.0)
    print(f"[BOOT] Emergency UDP listener on 0.0.0.0:{EMERG_UDP_PORT}")
    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(128)
        except socket.timeout:
            continue
        msg = data.decode(errors="ignore").strip().upper()
        with emergency_lock:
            if msg in EMERG_ON_STRINGS:
                if not emergency:
                    emergency = True
                    print(f"[EMERG] ON (from {addr[0]})")
            elif msg in EMERG_OFF_STRINGS:
                if emergency:
                    emergency = False
                    print(f"[EMERG] OFF (from {addr[0]})")
            else:
                print(f"[EMERG] Unknown command '{msg}' from {addr[0]}")
    sock.close()

def led_renderer():
    last_modes = (None, None)
    print("[BOOT] LED renderer started")
    while not stop_event.is_set():
        now = time.time()

        # small grace before going red
        with last_lldp_seen_lock:
            seen = last_lldp_seen
        if (seen is not None and
            (now - seen) > LLDP_OK_WINDOW_SEC and
            (now - seen) < (LLDP_OK_WINDOW_SEC + DOWN_GRACE_SEC)):
            modes = ("solid", "off")
        else:
            modes = compute_led_modes(now)

        if modes != last_modes:
            g, r = modes
            set_green(g)
            set_red(r)
            print(f"[LED] green={g}, red={r}")
            last_modes = modes

        time.sleep(RENDER_PERIOD_SEC)

def lldp_debug():
    """
    Every 2s print per-iface LLDP ages. Helps pinpoint which NIC sees frames.
    """
    while not stop_event.is_set():
        now = time.time()
        with per_iface_lock:
            lines = []
            for iface, ts in last_lldp_per_iface.items():
                if ts is None:
                    lines.append(f"{iface}: never")
                else:
                    lines.append(f"{iface}: {now - ts:.1f}s ago")
        print(f"[DBG] LLDP age per iface | window={LLDP_OK_WINDOW_SEC:.1f}s : " + ", ".join(lines))
        time.sleep(2.0)

# ------------------- Signals -------------------
def cleanup_and_exit(signum=None, frame=None):
    print("[EXIT] Stopping threads and cleaning up GPIO...")
    stop_event.set()
    try:
        green.off()
        red.off()
    except Exception:
        pass
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup_and_exit)
signal.signal(signal.SIGTERM, cleanup_and_exit)

# ------------------- CLI -------------------
def parse_args():
    p = argparse.ArgumentParser(description="LED agent: LLDP heartbeat + emergency override (explicit-iface)")
    p.add_argument("--iface", action="append", required=True,
                   help="Interface(s) to sniff LLDP on. Repeat for multiple, e.g., "
                        "--iface eth0 --iface enx00e04c680591")
    p.add_argument("--lldp-window", type=float, default=LLDP_OK_WINDOW_SEC,
                   help=f"Seconds considered connected after last LLDP (default: {LLDP_OK_WINDOW_SEC:.1f})")
    p.add_argument("--down-grace", type=float, default=DOWN_GRACE_SEC,
                   help=f"Hysteresis seconds before turning RED (default: {DOWN_GRACE_SEC:.1f})")
    p.add_argument("--accept-any-lldp", action="store_true",
                   help="Count any LLDP (not only Ryu's). Default: OFF.")
    p.add_argument("--debug-lldp-ages", action="store_true",
                   help="Print per-iface LLDP ages every 2s.")
    return p.parse_args()

# ------------------- Main -------------------
if __name__ == "__main__":
    args = parse_args()
    IFACES = args.iface
    LLDP_OK_WINDOW_SEC = args.lldp_window
    DOWN_GRACE_SEC = args.down_grace
    ACCEPT_ANY_LLDP = args.accept_any_lldp
    DEBUG_LLDP_AGES = args.debug_lldp_ages

    print("[BOOT] LED Agent starting (LLDP heartbeat + emergency override)")
    print(f"[BOOT] Params: IFACES={IFACES}  LLDP_WINDOW={LLDP_OK_WINDOW_SEC}s  DOWN_GRACE={DOWN_GRACE_SEC}s  "
          f"ACCEPT_ANY_LLDP={ACCEPT_ANY_LLDP} DEBUG={DEBUG_LLDP_AGES}")

    # small startup animation
    green.blink(on_time=0.2, off_time=0.2, n=3, background=False)
    red.off()
    green.off()

    t1 = threading.Thread(target=lldp_sniffer, daemon=True)
    t2 = threading.Thread(target=emergency_listener, daemon=True)
    t3 = threading.Thread(target=led_renderer, daemon=True)

    t1.start(); t2.start(); t3.start()

    if DEBUG_LLDP_AGES:
        t4 = threading.Thread(target=lldp_debug, daemon=True)
        t4.start()

    while not stop_event.is_set():
        time.sleep(1.0)
