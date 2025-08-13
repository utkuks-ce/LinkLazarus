#!/usr/bin/env python3
# led_agent.py
# Requirements: sudo apt-get install -y python3-gpiozero python3-scapy
# Run (single iface):   sudo -E python3 led_agent.py --iface eth0
# Run (multi-iface):    sudo -E python3 led_agent.py --iface eth0 --iface eth1
# Run (auto/"any"):     sudo -E python3 led_agent.py
# Emergency test: echo -n "EMERG 1" | nc -u <pi_ip> 9999   (ON)
#                  echo -n "EMERG 0" | nc -u <pi_ip> 9999   (OFF)

import argparse
import threading
import socket
import time
import signal
import sys
from typing import Optional, List, Union

from gpiozero import LED
from scapy.all import sniff, Ether, get_if_list  # LLDP: ethertype 0x88cc

# ------------------- Defaults -------------------
GREEN_PIN = 17
RED_PIN   = 27

LLDP_ETHERTYPE = 0x88CC
DEFAULT_LLDP_OK_WINDOW_SEC = 6.0   # LLDP görülmezse bu süre sonunda "connected" değil say
DEFAULT_DOWN_GRACE_SEC     = 1.0   # connected->disconnected geçişinde histerezis
RENDER_PERIOD_SEC          = 0.20  # LED renderer loop interval

EMERG_UDP_PORT = 9999
EMERG_ON_STRINGS  = {"EMERG 1", "EMERGENCY 1", "EMERGENCY ON", "EMERG ON", "ON"}
EMERG_OFF_STRINGS = {"EMERG 0", "EMERGENCY 0", "EMERGENCY OFF", "EMERG OFF", "OFF"}

# ------------------- Globals -------------------
last_lldp_seen_lock = threading.Lock()
last_lldp_seen: Optional[float] = None

emergency_lock = threading.Lock()
emergency = False

stop_event = threading.Event()

# CLI ile set edilecekler
LLDP_OK_WINDOW_SEC: float = DEFAULT_LLDP_OK_WINDOW_SEC
DOWN_GRACE_SEC: float = DEFAULT_DOWN_GRACE_SEC
IFACES: Optional[List[str]] = None  # None => otomatik seçim

# ------------------- LED helpers -------------------
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
    """
    Öncelik: emergency > connected > disconnected
    """
    with emergency_lock:
        is_emerg = emergency
    if is_emerg:
        return ("off", "solid")  # green off, red solid

    with last_lldp_seen_lock:
        seen = last_lldp_seen

    connected = (seen is not None) and ((now - seen) <= LLDP_OK_WINDOW_SEC)

    if connected:
        return ("solid", "off")        # green solid
    else:
        return ("off", "blink_slow")   # red slow blink

# ------------------- Threads -------------------
def lldp_sniffer():
    """
    Seçili iface(ler) üzerinden LLDP (0x88cc) dinler; paket gördükçe zaman damgasını günceller.
    """
    def on_pkt(pkt):
        if not pkt.haslayer(Ether):
            return
        eth = pkt[Ether]
        if eth.type != LLDP_ETHERTYPE:
            return
        now = time.time()
        with last_lldp_seen_lock:
            global last_lldp_seen
            last_lldp_seen = now
        # Çok log basmak istemezsen yorumsuz bırak:
        # print(f"[LLDP] seen at {now:.3f}")

    # iface seçim mantığı:
    # - IFACES listesi verilmişse onu kullan (list ver)
    # - verilmemişse önce 'any' arayüzünü dene (Linux'ta tüm arayüzler)
    # - 'any' yoksa/çalışmazsa iface parametresiz (Scapy default)
    iface_arg: Union[None, str, List[str]]
    if IFACES:
        iface_arg = IFACES
        print(f"[BOOT] Sniffing LLDP on IFACES={iface_arg}")
    else:
        try:
            # 'any' arayüzü çoğu Linux'ta vardır; listede olmasa da pcap destekliyorsa çalışır
            iface_arg = "any"
            print("[BOOT] No --iface provided; trying 'any' (all interfaces)")
        except Exception:
            iface_arg = None
            print("[BOOT] No --iface provided; using Scapy default interface")

    try:
        sniff(
            prn=on_pkt,
            filter="ether proto 0x88cc",
            store=0,
            iface=iface_arg,  # list | "any" | None
            stop_filter=lambda _: stop_event.is_set()
        )
    except Exception as e:
        print(f"[ERR] LLDP sniffer stopped: {e}")

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
        # kısa histerezis: kırmızıya dönmeden önce ufak bekleme
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

# ------------------- Signal handling -------------------
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
    p = argparse.ArgumentParser(description="LED agent: LLDP heartbeat + emergency override")
    p.add_argument("--iface", action="append",
                   help="Interface(s) to sniff LLDP on. Repeat for multiple "
                        "(e.g., --iface eth0 --iface eth1). If omitted, tries 'any', "
                        "else Scapy default.")
    p.add_argument("--lldp-window", type=float, default=DEFAULT_LLDP_OK_WINDOW_SEC,
                   help=f"Seconds to consider connected after last LLDP seen (default: {DEFAULT_LLDP_OK_WINDOW_SEC:.1f})")
    p.add_argument("--down-grace", type=float, default=DEFAULT_DOWN_GRACE_SEC,
                   help=f"Hysteresis seconds before turning red after LLDP gap (default: {DEFAULT_DOWN_GRACE_SEC:.1f})")
    return p.parse_args()

# ------------------- Main -------------------
if __name__ == "__main__":
    args = parse_args()
    IFACES = args.iface
    LLDP_OK_WINDOW_SEC = args.lldp_window
    DOWN_GRACE_SEC = args.down_grace

    print("[BOOT] LED Agent starting (LLDP heartbeat + emergency override)")
    print(f"[BOOT] Params: IFACES={IFACES if IFACES else '(auto)'}  "
          f"LLDP_WINDOW={LLDP_OK_WINDOW_SEC}s  DOWN_GRACE={DOWN_GRACE_SEC}s")

    # küçük başlangıç animasyonu
    green.blink(on_time=0.2, off_time=0.2, n=3, background=False)
    red.off(); green.off()

    t1 = threading.Thread(target=lldp_sniffer, daemon=True)
    t2 = threading.Thread(target=emergency_listener, daemon=True)
    t3 = threading.Thread(target=led_renderer, daemon=True)

    t1.start(); t2.start(); t3.start()

    # Sonsuz bekleme
    while True:
        time.sleep(1.0)
