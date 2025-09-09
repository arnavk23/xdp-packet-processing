set -e

# Setup veth pair and dependencies
sudo bash setup.sh

# Build project
make

# Attach XDP program to veth0
sudo ip link set dev veth0 xdp obj xdp_pass_kern.o sec xdp

# Start user-space forwarder
sudo ./user_forwarder --dev veth0 &
FORWARDER_PID=$!
sleep 2

# Generate traffic
ping -c 5 192.168.1.2 -I veth0

# Stop user-space forwarder
sudo kill $FORWARDER_PID

# Cleanup
sudo ip link set dev veth0 xdp off
sudo ip link set dev veth1 xdp off

echo "Demo complete. See README.md for detail information on the pipeline."
