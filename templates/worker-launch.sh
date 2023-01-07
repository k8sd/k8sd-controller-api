curl -fsSL https://tailscale.com/install.sh | sh
tailscale up --login-server https://{{ controller_domain }}:444 --accept-routes --auth-key {{ tailscale_preauth_key }}  \
  {{ tailscale_args }}


CONTROLLER="{{ controller_private_ip }}"
NODE_IP=`tailscale ip`
HOSTNAME=`hostname -s`
curl -sfL https://get.k3s.io | INSTALL_K3S_CHANNEL=v1.24 K3S_TOKEN={{ k3s_install_token }} INSTALL_K3S_EXEC="agent --flannel-iface=tailscale0 --node-name $HOSTNAME --node-ip $NODE_IP --node-external-ip $NODE_IP --server https://$CONTROLLER:6443 --kubelet-arg address=$NODE_IP" sh -s - 

# --kube-proxy-arg nodeport-addresses=100.64.0.0/8

apt install -y haproxy
# Base case attempts to serve the ingress on public IPs. Only does ipv4 for now
# generate haproxy configuration
PROXY_CONFIG_FILE=/etc/haproxy/haproxy.cfg
echo "
global
        log /dev/log    local0
        log /dev/log    local1 notice
        chroot /var/lib/haproxy
        stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
        stats timeout 30s
        user haproxy
        group haproxy
        daemon

        # Default SSL material locations
        ca-base /etc/ssl/certs
        crt-base /etc/ssl/private

        # See: https://ssl-config.mozilla.org/#server=haproxy&server-version=2.0.3&config=intermediate
        ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
        ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
        ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
        log     global
        mode    tcp
        option  tcplog
        option  dontlognull
        timeout connect 5000
        timeout client  120000
        timeout server  120000
        errorfile 400 /etc/haproxy/errors/400.http
        errorfile 403 /etc/haproxy/errors/403.http
        errorfile 408 /etc/haproxy/errors/408.http
        errorfile 500 /etc/haproxy/errors/500.http
        errorfile 502 /etc/haproxy/errors/502.http
        errorfile 503 /etc/haproxy/errors/503.http
        errorfile 504 /etc/haproxy/errors/504.http

frontend https
         bind $NODE_IP:443
" > $PROXY_CONFIG_FILE
for i in `ip addr sho | grep inet | grep -vE 'flannel|tailscale|cni|calico|inet6' | grep global | cut -f 6 -d " " | cut -f 1 -d "/"`; do
  echo "         bind $i:443" >> $PROXY_CONFIG_FILE
done
echo "
         mode tcp
         default_backend bk_app
{% if ip_whitelisting == True %}
         tcp-request connection reject if ! { src -f /etc/haproxy/ip-whitelist.txt }
{% endif %}

backend bk_app
         mode tcp
         server ingress-k8s 10.43.8.254:443

frontend http
         bind $NODE_IP:80
" >> $PROXY_CONFIG_FILE
for i in `ip addr sho | grep inet | grep -vE 'flannel|tailscale|cni|calico|inet6' | grep global | cut -f 6 -d " " | cut -f 1 -d "/"`; do
  echo "         bind $i:80" >> $PROXY_CONFIG_FILE
done
echo '
         mode tcp
         default_backend bk_http
{% if ip_whitelisting == True %}
         tcp-request connection reject if ! { src -f /etc/haproxy/ip-whitelist.txt }
{% endif %}

backend bk_http
         mode tcp
         server ingress-k8s 10.43.8.254:80
' >> $PROXY_CONFIG_FILE

echo "
{%- for line in whitelisted_ips %}
{{ line -}}
{% endfor %}
" > /etc/haproxy/ip-whitelist.txt

service haproxy reload || service haproxy restart

#Setup systemd based checkin
echo "[Unit]
Description=Connects and updates configuration for k8sd worker nodes
Wants=k8sd-worker.timer

[Service]
Type=oneshot
ExecStart=/usr/bin/bash -c 'curl -sfL curl https://{{ controller_domain }}/cluster/connect/worker/{{ worker_key }} | sh'

[Install]
WantedBy=multi-user.target
" > /etc/systemd/system/k8sd-worker.service

echo "[Unit]
Description=k8sd worker checkin job
Requires=k8sd-worker.service

[Timer]
Unit=k8sd-worker.service
OnCalendar=*-*-* *:1/5:00

[Install]
WantedBy=timers.target
" > /etc/systemd/system/k8sd-worker.timer

systemctl start k8sd-worker.timer
systemctl enable k8sd-worker.timer