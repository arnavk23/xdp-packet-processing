# Setup veth pair and dependencies for XDP/AF_XDP demo
set -e

# Create veth pair
ip link add veth0 type veth peer name veth1
ip link set veth0 up
ip link set veth1 up

# Assign IPs
ip addr add 192.168.1.1/24 dev veth0
ip addr add 192.168.1.2/24 dev veth1

# Install dependencies
apt-get update
apt-get install -y clang llvm libbpf-dev gcc make iproute2

# Enable XDP on veth0
ethtool -K veth0 xdp on

# Show veth status
ip link show veth0
ip link show veth1

echo "Setup complete. veth0 and veth1 are ready for XDP/AF_XDP demo."
