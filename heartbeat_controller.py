import requests
import threading
import time
import logging

# ==== Ayarlar ====
PI_IPS = ["192.168.1.2", "192.168.56.3", "192.168.1.4", "192.168.1.5"]
PORT = 5000
HEARTBEAT_INTERVAL = 3  # saniye
TIMEOUT = 2  # request timeout süresi
STATUS_CHECK_INTERVAL = 15  # saniye

# ==== Log Ayarı ====
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ==== Global Durumlar ====
last_status = {}  # {"192.168.1.101": "OK" / "ERROR"}
lock = threading.Lock()

# ==== Heartbeat Gönderici ====
def send_heartbeat(ip):
    url = f"http://{ip}:{PORT}/led"
    payload = {"status": "normal"}

    while True:
        try:
            response = requests.post(url, json=payload, timeout=TIMEOUT)
            with lock:
                if response.status_code == 200:
                    if last_status.get(ip) != "OK":
                        logging.info(f"[{ip}] ✅ Bağlantı sağlandı.")
                        last_status[ip] = "OK"
                else:
                    if last_status.get(ip) != "ERROR":
                        logging.warning(f"[{ip}] ⚠️ Hata: {response.status_code} - {response.text}")
                        last_status[ip] = "ERROR"
        except requests.exceptions.RequestException as e:
            with lock:
                if last_status.get(ip) != "ERROR":
                    logging.error(f"[{ip}] ❌ Bağlantı hatası: {e}")
                    last_status[ip] = "ERROR"

        time.sleep(HEARTBEAT_INTERVAL)

# ==== Durum Sorgulama (opsiyonel) ====
def check_status(ip):
    url = f"http://{ip}:{PORT}/status"

    while True:
        try:
            response = requests.get(url, timeout=TIMEOUT)
            if response.status_code == 200:
                data = response.json()
                logging.info(f"[{ip}] 📡 Durum: {data.get('status')}")
            else:
                logging.warning(f"[{ip}] Durum alınamadı: {response.status_code}")
        except Exception as e:
            logging.error(f"[{ip}] Durum alınamadı: {e}")

        time.sleep(STATUS_CHECK_INTERVAL)

# ==== Ana ====
if __name__ == "__main__":
    for ip in PI_IPS:
        threading.Thread(target=send_heartbeat, args=(ip,), daemon=True).start()
        threading.Thread(target=check_status, args=(ip,), daemon=True).start()

    # Sonsuza kadar bekle
    while True:
        time.sleep(60)
