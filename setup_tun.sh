sudo ip tuntap add name ogstun mode tun
sudo ip addr add 10.45.0.1/16 dev ogstun
sudo ip addr add 2001:230:cafe::1/48 dev ogstun
sudo ip link set ogstun up

#sudo systemctl start mongodb (if '/usr/bin/mongod' is not running)
#sudo systemctl enable mongodb (ensure to automatically start it on system boot)
