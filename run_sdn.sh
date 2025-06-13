#!/bin/bash

# Ayarlar
VENV_DIR=~/Desktop/LinkLazarus/ryu_env
RYU_PATH=~/Desktop/LinkLazarus/ryu_path_controller.py

# 1. Ryu terminali
echo "[INFO] Ryu terminali başlatılıyor..."
xterm -hold -e "bash --login -i -c '
cd ~/Desktop/LinkLazarus &&
source $VENV_DIR/bin/activate &&
ryu-manager --observe-links --ofp-tcp-listen-port 6653 $RYU_PATH
'" &

sleep 5

# 2. Mininet terminali
echo "[INFO] Mininet terminali başlatılıyor..."
xterm -hold -e "bash --login -i -c '
sudo mn --topo linear,4 --controller=remote,ip=127.0.0.1,port=6653 --switch ovs,protocols=OpenFlow13 --mac
'" &

sleep 5

# 3. Flow table dump terminali
echo "[INFO] Flow dump terminali başlatılıyor..."
xterm -hold -e "bash --login -i -c '
sleep 10 &&
for s in s1 s2 s3 s4; do
  echo \"--- \$s ---\"
  sudo ovs-ofctl -O OpenFlow13 dump-flows \$s
done
'" &

echo "[INFO] Tüm terminaller başarıyla başlatıldı."
