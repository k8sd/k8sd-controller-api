curl -fsSL https://tailscale.com/install.sh | sh
tailscale up --login-server https://{{ controller_domain }}:444 --accept-routes --auth-key {{ tailscale_preauth_key }}  \
  {{ tailscale_args }}


CONTROLLER="{{ controller_private_ip }}"
NODE_IP=`tailscale ip`
HOSTNAME=`hostname -s`
curl -sfL https://get.k3s.io | INSTALL_K3S_CHANNEL=v1.24 K3S_TOKEN={{ k3s_install_token }} INSTALL_K3S_EXEC="agent --flannel-iface=tailscale0 --node-name $HOSTNAME --node-ip $NODE_IP --node-external-ip $NODE_IP --server https://$CONTROLLER:6443 --kubelet-arg address=$NODE_IP" sh -s - 

# --kube-proxy-arg nodeport-addresses=100.64.0.0/8




