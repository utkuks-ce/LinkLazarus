#code on pi

from flask import Flask, request, jsonify
import RPi.GPIO as GPIO
import atexit
import threading
import time

app = Flask(__name__)

# ==== Ayarlar ====
GREEN_LED = 17
RED_LED = 27
HEARTBEAT_TIMEOUT = 6  # saniye

# ==== GPIO Başlat ====
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)
GPIO.setup(GREEN_LED, GPIO.OUT)
GPIO.setup(RED_LED, GPIO.OUT)
GPIO.output(GREEN_LED, GPIO.LOW)
GPIO.output(RED_LED, GPIO.LOW)

# ==== Temizlik ====
def cleanup_gpio():
    GPIO.cleanup()
atexit.register(cleanup_gpio)

# ==== Global Durumlar ====
last_heartbeat = time.time()
manual_emergency = False
lock = threading.Lock()

# ==== LED Güncelleme Fonksiyonu ====
def update_leds(state):
    if state == "normal":
        GPIO.output(GREEN_LED, GPIO.HIGH)
        GPIO.output(RED_LED, GPIO.LOW)
    elif state == "emergency":
        GPIO.output(GREEN_LED, GPIO.LOW)
        GPIO.output(RED_LED, GPIO.HIGH)
    elif state == "off":
        GPIO.output(GREEN_LED, GPIO.LOW)
        GPIO.output(RED_LED, GPIO.LOW)

# ==== Heartbeat Takip Thread'i ====
def heartbeat_monitor():
    global manual_emergency
    while True:
        with lock:
            elapsed = time.time() - last_heartbeat
            if not manual_emergency and elapsed > HEARTBEAT_TIMEOUT:
                update_leds("emergency")
        time.sleep(1)

threading.Thread(target=heartbeat_monitor, daemon=True).start()

# ==== API: LED Kontrol ====
@app.route('/led', methods=['POST'])
def control_led():
    global last_heartbeat, manual_emergency
    data = request.get_json()

    if not data or "status" not in data:
        return "Eksik veri! JSON içinde 'status' anahtarı olmalı.", 400

    with lock:
        status = data["status"]
        if status == "normal":
            manual_emergency = False
            last_heartbeat = time.time()
            update_leds("normal")
            return "Normal mod: yeşil LED açık", 200

        elif status == "emergency":
            manual_emergency = True
            update_leds("emergency")
            return "Acil durum: kırmızı LED açık", 200

        elif status == "off":
            manual_emergency = False
            update_leds("off")
            return "LED'ler kapatıldı", 200

        else:
            return "Geçersiz 'status' değeri. Beklenen: normal, emergency, off", 400

# ==== API: Sağlık Kontrolü ====
@app.route('/health', methods=['GET'])
def health_check():
    return "OK", 200

# ==== API: Durum Sorgulama ====
@app.route('/status', methods=['GET'])
def get_status():
    with lock:
        elapsed = time.time() - last_heartbeat
        if manual_emergency:
            status = "emergency"
        elif elapsed <= HEARTBEAT_TIMEOUT:
            status = "normal"
        else:
            status = "emergency"
    return jsonify({"status": status}), 200

# ==== Uygulama Başlat ====
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
