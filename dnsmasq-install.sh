#!/usr/bin/env bash
sudo ss -lp "sport = :domain"
# Disable any service that is running on this port. It's usually systemd-resolved.
sudo systemctl disable systemd-resolved
sudo systemctl stop systemd-resolved
#  also mask it so it doesn't auto start on reboot.
sudo systemctl mask systemd-resolved
echo -e '[main]\nplugins=ifupdown,keyfile\ndns=none\n[ifupdown]\nmanaged=false\n[device]\nwifi.scan-rand-mac-address=no' > /etc/NetworkManager/NetworkManager.conf
echo -e 'port=53\ndomain-needed\nbogus-priv\nbind-interfaces\nresolv-file=/etc/dnsmasq-resolv.conf\nstrict-order\nexpand-hosts\nconf-dir=/etc/dnsmasq.d\nlisten-address=::1,127.0.0.1\naddn-hosts=/etc/dnsmasq.hosts\n' > /etc/dnsmasq.conf
echo -e 'nameserver 127.0.0.1\n' > /etc/resolv.conf
echo -e 'nameserver 8.8.8.8\nnameserver 8.8.8.4' > /etc/dnsmasq-resolv.conf

systemctl restart network-manager.service
systemctl restart dnsmasq.service