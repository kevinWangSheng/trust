cargo b --release
sudo setcap cap_net_admin=eip ./target/release/trust
./target/release/trust
pid=$!
sudo ip addr add 192.168.7.1 dev tun0
sudo ip link set up dev tun0
trap kill $pid TERM
wait $pid