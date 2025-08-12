#Run on pi
#Run with: sudo -E python3 led_agent.py --iface eth0 --iface eth1
#!/usr/bin/env python3
# led_agent.py
# Requirements: sudo apt-get install -y python3-gpiozero python3-scapy
# Run (örnek): sudo -E python3 led_agent.py --iface eth0 --window 5
# Emergency test: echo -n "EMERG 1" | nc -u <pi_ip> 9999   (ON)
#                 echo -n "EMERG 0" | nc -u <pi_ip> 9999   (OFF)

import argparse
import threading
import socket
import time
import signal
import sys
from typing import Optional, List

from gpiozero import LED
from scapy.all import sniff, Ether  # LLDP = ethertype 0x88cc

# ------------------- Defaults -------------------
GREEN_PIN = 17
RED_PIN   = 27

LLDP_ETHERTYPE = 0x88CC
DEFAULT_WINDOW_SEC = 4.0       # LLDP görülmezse bu süre sonunda "disconnected"
DOWN_GRACE_SEC     = 1.0       # connected->disconnected geçişinde histerezis
RENDER_PERIOD_SEC  = 0.20      # LED renderer loop interval

EMERG_UDP_PORT = 9999
EMERG_ON_STRINGS  = {"EMERG 1", "EMERGENCY 1", "EMERGENCY ON", "EMERG ON", "ON"}
EMERG_OFF_STRINGS = {"EMERG 0", "EMERGENCY 0", "EMERGENCY OFF", "EMERG OFF", "OFF"}

# ------------------- Globals -------------------
last_lldp_seen_lock = threading.Lock()
last_lldp_seen: Optional[float] = None

emergency_lock = threading.Lock()
emergency = False

stop_event = threading.Event()

# GPIO
green = LED(GREEN_PIN)
red   = LED(RED_PIN)

# Arg-parsed config (runtime)
IFACES: List[str] = []
LLDP_OK_WINDOW_SEC: float = DEFAULT_WINDOW_SEC


# ------------------- LED helpers -------------------
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
        is_emerg = emergency
    if is_emerg:
        return ("off", "solid")

    with last_lldp_seen_lock:
        seen = last_lldp_seen

    if seen is None:
        connected = False
    else:
        age = now - seen
        connected = age <= LLDP_OK_WINDOW_SEC

    if connected:
        return ("solid", "off")
    else:
        return ("off", "blink_slow")


# ------------------- Threads -------------------
def lldp_sniffer():
    """
    Seçilen arayüz(ler)de LLDP (0x88cc) gördüğünde zaman damgasını günceller.
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
        # arada bir log
        print(f"[LLDP] frame seen at t={now:.3f}")

    try:
        print(f"[BOOT] Sniffing LLDP on ifaces: {IFACES or ['<auto>']}, window={LLDP_OK_WINDOW_SEC}s")
        sniff(
            iface=IFACES if IFACES else None,    # none => scapy kendi seçer (linux’ta genelde 'any')
            prn=on_pkt,
            filter="ether proto 0x88cc",
            store=0,
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

        # küçük bir grace: bağlantı kopuşunda hemen kırmızıya düşmemek için
        with last_lldp_seen_lock:
            seen = last_lldp_seen
        if seen is not None and (now - seen) > LLDP_OK_WINDOW_SEC and (now - seen) < (LLDP_OK_WINDOW_SEC + DOWN_GRACE_SEC):
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


# ------------------- Main -------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LLDP heartbeat + emergency LED agent")
    parser.add_argument("--iface", action="append", help="Interface(s) to sniff LLDP on (repeatable), e.g. --iface eth0", default=[])
    parser.add_argument("--window", type=float, default=DEFAULT_WINDOW_SEC, help="LLDP ok window in seconds")
    args = parser.parse_args()

    IFACES = args.iface or []       # boş ise scapy auto
    LLDP_OK_WINDOW_SEC = float(args.window)

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    print("[BOOT] LED Agent starting (LLDP heartbeat + emergency override)")
    # küçük başlangıç animasyonu
    green.blink(on_time=0.2, off_time=0.2, n=3, background=False)
    red.off()
    green.off()

    t1 = threading.Thread(target=lldp_sniffer, daemon=True)
    t2 = threading.Thread(target=emergency_listener, daemon=True)
    t3 = threading.Thread(target=led_renderer, daemon=True)

    t1.start(); t2.start(); t3.start()

    while True:
        time.sleep(1.0)
